// gate puts passkey (WebAuthn) login in front of ttyd. After a passkey login it proxies
// every request, websockets included, to ttyd's UNIX socket and sets the header that
// ttyd's --auth-header trusts; ttyd itself is reachable only through that socket.
// It also serves GATE_FILES read-only at /files/ (see files.go).
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/net/webdav"
)

const (
	sessionCookie   = "gate_session"
	ceremonyCookie  = "gate_ceremony"
	ceremonyTimeout = 5 * time.Minute
	minSetupCode    = 16
	maxNameLen      = 64
)

//go:embed pages
var pages embed.FS

var tmpl = template.Must(template.ParseFS(pages, "pages/*.html"))

type config struct {
	Origin     string        // GATE_ORIGIN: the URL the browser uses, e.g. https://claude.example.ts.net
	Listen     string        // GATE_LISTEN
	Backend    string        // GATE_BACKEND: ttyd's UNIX socket
	DataDir    string        // GATE_DATA: passkeys and the session key
	AuthHeader string        // GATE_AUTH_HEADER: must match ttyd's --auth-header
	SetupCode  string        // GATE_SETUP_CODE: allows registering a passkey without one
	Files      string        // GATE_FILES: the directory served at /files/ (read-only) and /dav/
	SessionTTL time.Duration // GATE_SESSION_DAYS
}

type ceremony struct {
	data    webauthn.SessionData
	name    string // registration only: what to call the new passkey
	expires time.Time
}

type gate struct {
	cfg    config
	secure bool
	wa     *webauthn.WebAuthn
	st     *store
	proxy  http.Handler
	files  *os.Root        // nil when GATE_FILES can't be opened
	dav    *webdav.Handler // nil with files

	mu         sync.Mutex
	ceremonies map[string]ceremony
	setupMu    sync.Mutex // serialises setup-code checks, which are slowed on failure
}

func main() {
	cfg := config{
		Origin:     os.Getenv("GATE_ORIGIN"),
		Listen:     envOr("GATE_LISTEN", ":8080"),
		Backend:    envOr("GATE_BACKEND", "/tty/ttyd.sock"),
		DataDir:    envOr("GATE_DATA", "/data"),
		AuthHeader: envOr("GATE_AUTH_HEADER", "X-Auth-User"),
		SetupCode:  strings.TrimSpace(os.Getenv("GATE_SETUP_CODE")),
		Files:      envOr("GATE_FILES", "/files"),
		SessionTTL: 30 * 24 * time.Hour,
	}
	os.Unsetenv("GATE_SETUP_CODE")
	if d := os.Getenv("GATE_SESSION_DAYS"); d != "" {
		n, err := strconv.Atoi(d)
		if err != nil || n < 1 {
			log.Fatalf("gate: GATE_SESSION_DAYS must be a whole number of days, got %q", d)
		}
		cfg.SessionTTL = time.Duration(n) * 24 * time.Hour
	}
	g, err := newGate(cfg)
	if err != nil {
		log.Fatalf("gate: %v", err)
	}
	switch {
	case cfg.SetupCode != "" && g.st.hasCredentials():
		log.Printf("gate: GATE_SETUP_CODE is set; remove it once your passkeys are registered")
	case cfg.SetupCode != "":
		log.Printf("gate: no passkeys yet; register one at %s/auth/register with the setup code", cfg.Origin)
	case !g.st.hasCredentials():
		log.Printf("gate: no passkeys and no GATE_SETUP_CODE; nobody can log in until one is set")
	}
	srv := &http.Server{Addr: cfg.Listen, Handler: g, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("gate: listening on %s for %s, proxying to %s", cfg.Listen, cfg.Origin, cfg.Backend)
	log.Fatal(srv.ListenAndServe())
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func newGate(cfg config) (*gate, error) {
	u, err := url.Parse(cfg.Origin)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.Path != "" {
		return nil, errors.New("GATE_ORIGIN must be the terminal's URL with no path, e.g. https://claude.example.ts.net")
	}
	if cfg.SetupCode != "" && len(cfg.SetupCode) < minSetupCode {
		return nil, errors.New("GATE_SETUP_CODE is too short; use e.g. `openssl rand -hex 16`")
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          u.Hostname(),
		RPDisplayName: "claude",
		RPOrigins:     []string{cfg.Origin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		},
	})
	if err != nil {
		return nil, err
	}
	st, err := openStore(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	g := &gate{cfg: cfg, secure: u.Scheme == "https", wa: wa, st: st, ceremonies: map[string]ceremony{}}
	if cfg.Files != "" {
		if g.files, err = os.OpenRoot(cfg.Files); err != nil {
			log.Printf("gate: /files/ and /dav/ are off: %v", err)
		} else {
			g.dav = newDav(g.files)
		}
	}
	g.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = "ttyd"
			pr.Out.Host = "localhost"
			pr.Out.Header.Del(cfg.AuthHeader)
			pr.Out.Header.Set(cfg.AuthHeader, "claude")
			// The gate's own cookies are no business of ttyd's (or the shell's).
			pr.Out.Header.Del("Cookie")
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", cfg.Backend)
			},
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				return // the browser went away
			}
			log.Printf("gate: proxy: %v", err)
			http.Error(w, "The terminal isn't running (ttyd unreachable).", http.StatusBadGateway)
		},
	}
	return g, nil
}

func (g *gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/auth/") {
		g.serveAuth(w, r)
		return
	}
	// Token auth, not the session cookie; see dav.go.
	if r.URL.Path == "/dav" || strings.HasPrefix(r.URL.Path, "/dav/") {
		g.serveDav(w, r)
		return
	}
	if !g.loggedIn(r) {
		if r.Method == http.MethodGet && r.Header.Get("Upgrade") == "" {
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		} else {
			http.Error(w, "not logged in", http.StatusUnauthorized)
		}
		return
	}
	if r.URL.Path == "/files" || strings.HasPrefix(r.URL.Path, "/files/") {
		g.serveFiles(w, r)
		return
	}
	// Websockets carry the session cookie automatically; only accept them from our page.
	if r.Header.Get("Upgrade") != "" && !g.sameOrigin(r) {
		http.Error(w, "cross-origin websocket refused", http.StatusForbidden)
		return
	}
	g.proxy.ServeHTTP(w, r)
}

func (g *gate) serveAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if !g.sameOrigin(r) {
			http.Error(w, "cross-origin request refused", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /auth/login":
		g.page(w, r, "login.html")
	case "GET /auth/register":
		g.page(w, r, "register.html")
	case "GET /auth/gate.js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		b, _ := pages.ReadFile("pages/gate.js")
		w.Write(b)
	case "POST /auth/login/begin":
		g.loginBegin(w, r)
	case "POST /auth/login/finish":
		g.loginFinish(w, r)
	case "POST /auth/register/begin":
		g.registerBegin(w, r)
	case "POST /auth/register/finish":
		g.registerFinish(w, r)
	case "GET /auth/manage":
		if !g.loggedIn(r) {
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}
		g.page(w, r, "manage.html")
	case "POST /auth/manage/rename", "POST /auth/manage/remove", "POST /auth/manage/signout-others",
		"POST /auth/manage/token-create", "POST /auth/manage/token-revoke":
		g.manage(w, r)
	case "GET /auth/logout", "POST /auth/logout":
		http.SetCookie(w, g.cookie(sessionCookie, "", "/", -1))
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
	default:
		http.NotFound(w, r)
	}
}

func (g *gate) page(w http.ResponseWriter, r *http.Request, name string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; "+
			"base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	current, loggedIn := g.session(r)
	tmpl.ExecuteTemplate(w, name, map[string]any{
		"LoggedIn":     loggedIn,
		"Current":      current,
		"HasPasskeys":  g.st.hasCredentials(),
		"SetupEnabled": g.cfg.SetupCode != "",
		"Passkeys":     g.st.passkeys(),
		"Tokens":       g.st.tokens(),
		"DavURL":       g.cfg.Origin + "/dav/",
	})
}

func (g *gate) loginBegin(w http.ResponseWriter, r *http.Request) {
	opts, data, err := g.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err)
		return
	}
	g.startCeremony(w, data, "")
	writeJSON(w, opts)
}

func (g *gate) loginFinish(w http.ResponseWriter, r *http.Request) {
	cer, ok := g.takeCeremony(w, r)
	if !ok {
		jsonError(w, http.StatusBadRequest, errors.New("login expired; try again"))
		return
	}
	data := cer.data
	own := g.st.snapshot()
	_, cred, err := g.wa.FinishPasskeyLogin(func(_, userHandle []byte) (webauthn.User, error) {
		if !bytes.Equal(userHandle, own.ID) {
			return nil, errors.New("unknown passkey")
		}
		return own, nil
	}, data, r)
	if err != nil {
		log.Printf("gate: login failed from %s: %v", r.RemoteAddr, err)
		jsonError(w, http.StatusUnauthorized, errors.New("that passkey wasn't accepted"))
		return
	}
	if cred.Authenticator.CloneWarning {
		log.Printf("gate: refusing passkey %x: its signature counter went backwards (possible clone)", cred.ID)
		jsonError(w, http.StatusUnauthorized, errors.New("that passkey wasn't accepted"))
		return
	}
	if err := g.st.updateCredential(*cred); err != nil {
		log.Printf("gate: saving sign count: %v", err)
	}
	g.startSession(w, credID(cred.ID))
	writeJSON(w, map[string]string{"next": "/"})
}

func (g *gate) registerBegin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
		Name string `json:"name"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	name, err := cleanName(body.Name, true)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err)
		return
	}
	if !g.loggedIn(r) && !g.checkSetupCode(body.Code) {
		jsonError(w, http.StatusForbidden, errors.New("wrong setup code"))
		return
	}
	own := g.st.snapshot()
	var exclude []protocol.CredentialDescriptor
	for _, c := range own.Credentials {
		exclude = append(exclude, c.Descriptor())
	}
	opts, data, err := g.wa.BeginRegistration(own, webauthn.WithExclusions(exclude))
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err)
		return
	}
	g.startCeremony(w, data, name)
	writeJSON(w, opts)
}

func (g *gate) registerFinish(w http.ResponseWriter, r *http.Request) {
	cer, ok := g.takeCeremony(w, r)
	if !ok {
		jsonError(w, http.StatusBadRequest, errors.New("registration expired; start again"))
		return
	}
	data := cer.data
	cred, err := g.wa.FinishRegistration(g.st.snapshot(), data, r)
	if err != nil {
		log.Printf("gate: registration failed from %s: %v", r.RemoteAddr, err)
		jsonError(w, http.StatusBadRequest, errors.New("the passkey couldn't be registered"))
		return
	}
	if err := g.st.addCredential(*cred, cer.name); err != nil {
		jsonError(w, http.StatusInternalServerError, err)
		return
	}
	log.Printf("gate: registered passkey %s (%q)", credID(cred.ID), cer.name)
	// Registering signs you in, unless you already were (a passkey added from the manage page).
	if !g.loggedIn(r) {
		g.startSession(w, credID(cred.ID))
		writeJSON(w, map[string]string{"next": "/"})
		return
	}
	writeJSON(w, map[string]string{"next": "/auth/manage"})
}

// manage handles the signed-in passkey management actions.
func (g *gate) manage(w http.ResponseWriter, r *http.Request) {
	current, ok := g.session(r)
	if !ok {
		jsonError(w, http.StatusUnauthorized, errors.New("not signed in"))
		return
	}
	var body struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	next := "/auth/manage"
	var err error
	switch r.URL.Path {
	case "/auth/manage/rename":
		var name string
		if name, err = cleanName(body.Name, false); err == nil {
			err = g.st.rename(body.ID, name)
		}
	case "/auth/manage/remove":
		if err = g.st.remove(body.ID); err == nil {
			log.Printf("gate: removed passkey %s", body.ID)
			// Its sessions end with it, this browser's included if it signed in with it.
			if body.ID == current {
				next = "/auth/login"
			}
		}
	case "/auth/manage/signout-others":
		if err = g.st.rotateKey(); err == nil {
			log.Printf("gate: signed out all other browsers")
			g.startSession(w, current)
		}
	case "/auth/manage/token-create":
		var name, tok string
		if name, err = cleanName(body.Name, false); err == nil {
			if tok, err = g.st.addToken(name); err == nil {
				log.Printf("gate: created WebDAV token %q", name)
				writeJSON(w, map[string]string{"token": tok, "next": next})
				return
			}
		}
	case "/auth/manage/token-revoke":
		if err = g.st.revokeToken(body.ID); err == nil {
			log.Printf("gate: revoked WebDAV token %s", body.ID)
		}
	}
	if err != nil {
		jsonError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, map[string]string{"next": next})
}

// cleanName trims a passkey name and checks its length; empty is allowed only when
// a default will be filled in.
func cleanName(s string, emptyOK bool) (string, error) {
	s = strings.Join(strings.Fields(s), " ")
	switch {
	case s == "" && !emptyOK:
		return "", errors.New("give it a name")
	case utf8.RuneCountInString(s) > maxNameLen:
		return "", errors.New("that name is too long")
	}
	return s, nil
}

// checkSetupCode compares in constant time and, on a wrong code, holds the lock for a
// second so guesses can't be made in parallel or quickly.
func (g *gate) checkSetupCode(code string) bool {
	if g.cfg.SetupCode == "" {
		return false
	}
	g.setupMu.Lock()
	defer g.setupMu.Unlock()
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(code)), []byte(g.cfg.SetupCode)) == 1 {
		return true
	}
	time.Sleep(time.Second)
	return false
}

// startCeremony keeps the WebAuthn challenge server-side, keyed by a random cookie.
func (g *gate) startCeremony(w http.ResponseWriter, data *webauthn.SessionData, name string) {
	id := randomID()
	now := time.Now()
	g.mu.Lock()
	for k, c := range g.ceremonies {
		if now.After(c.expires) {
			delete(g.ceremonies, k)
		}
	}
	g.ceremonies[id] = ceremony{data: *data, name: name, expires: now.Add(ceremonyTimeout)}
	g.mu.Unlock()
	http.SetCookie(w, g.cookie(ceremonyCookie, id, "/auth/", int(ceremonyTimeout/time.Second)))
}

// takeCeremony returns the challenge for this browser's ceremony; each is usable once.
func (g *gate) takeCeremony(w http.ResponseWriter, r *http.Request) (ceremony, bool) {
	http.SetCookie(w, g.cookie(ceremonyCookie, "", "/auth/", -1))
	c, err := r.Cookie(ceremonyCookie)
	if err != nil {
		return ceremony{}, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	cer, ok := g.ceremonies[c.Value]
	delete(g.ceremonies, c.Value)
	if !ok || time.Now().After(cer.expires) {
		return ceremony{}, false
	}
	return cer, true
}

// Sessions are "<expiry>.<passkey id>.<hmac>", signed with session.key. A session lasts
// until it expires, its passkey is removed, or the key is replaced (which signs out
// every browser).
func (g *gate) startSession(w http.ResponseWriter, cred string) {
	exp := make([]byte, 8)
	binary.BigEndian.PutUint64(exp, uint64(time.Now().Add(g.cfg.SessionTTL).Unix()))
	v := b64(exp) + "." + cred + "." + b64(g.sign(exp, cred))
	http.SetCookie(w, g.cookie(sessionCookie, v, "/", int(g.cfg.SessionTTL/time.Second)))
}

// session returns the passkey this browser signed in with, if its session is valid.
func (g *gate) session(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 3 {
		return "", false
	}
	exp, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	mac, err2 := base64.RawURLEncoding.DecodeString(parts[2])
	cred := parts[1]
	if err1 != nil || err2 != nil || len(exp) != 8 || !hmac.Equal(mac, g.sign(exp, cred)) {
		return "", false
	}
	if time.Now().Unix() >= int64(binary.BigEndian.Uint64(exp)) || !g.st.hasCredential(cred) {
		return "", false
	}
	return cred, true
}

func (g *gate) loggedIn(r *http.Request) bool {
	_, ok := g.session(r)
	return ok
}

func (g *gate) sign(exp []byte, cred string) []byte {
	m := hmac.New(sha256.New, g.st.sessionKey())
	m.Write([]byte("gate-session:"))
	m.Write(exp)
	m.Write([]byte(":" + cred))
	return m.Sum(nil)
}

func (g *gate) cookie(name, value, path string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: name, Value: value, Path: path, MaxAge: maxAge,
		HttpOnly: true, Secure: g.secure, SameSite: http.SameSiteStrictMode,
	}
}

func (g *gate) sameOrigin(r *http.Request) bool {
	return r.Header.Get("Origin") == g.cfg.Origin
}

func randomID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return b64(b)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
