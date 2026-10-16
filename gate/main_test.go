package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
)

const origin = "https://claude.example.test"

var rp = virtualwebauthn.RelyingParty{Name: "claude", ID: "claude.example.test", Origin: origin}

// fakeTTYD serves on a UNIX socket like ttyd: it reports the auth header and cookies it
// received, and answers websocket upgrades with 101 and then echoes.
func fakeTTYD(t *testing.T) string {
	sock := filepath.Join(t.TempDir(), "t.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			conn, rw, _ := w.(http.Hijacker).Hijack()
			defer conn.Close()
			rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			rw.Flush()
			io.Copy(conn, rw)
			return
		}
		fmt.Fprintf(w, "user=%s cookie=%q", r.Header.Get("X-Auth-User"), r.Header.Get("Cookie"))
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return sock
}

func newTestGate(t *testing.T, setupCode string) *gate {
	g, err := newGate(config{
		Origin: origin, Backend: fakeTTYD(t), DataDir: t.TempDir(),
		AuthHeader: "X-Auth-User", SetupCode: setupCode, SessionTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// browser keeps cookies by name (the gate's are Secure, so a cookie jar over plain
// HTTP wouldn't send them) and sends same-origin requests.
type browser struct {
	t       *testing.T
	g       *gate
	cookies map[string]string
}

func newBrowser(t *testing.T, g *gate) *browser {
	return &browser{t: t, g: g, cookies: map[string]string{}}
}

func (b *browser) prepare(r *http.Request) {
	r.Header.Set("Origin", origin)
	for k, v := range b.cookies {
		r.AddCookie(&http.Cookie{Name: k, Value: v})
	}
}

func (b *browser) keep(res *http.Response) {
	for _, c := range res.Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c.Value
		}
	}
}

func (b *browser) do(method, path, body string) (int, string) {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	b.prepare(r)
	w := httptest.NewRecorder()
	b.g.ServeHTTP(w, r)
	b.keep(w.Result())
	return w.Code, w.Body.String()
}

func (b *browser) must(method, path, body string) string {
	b.t.Helper()
	code, out := b.do(method, path, body)
	if code != http.StatusOK {
		b.t.Fatalf("%s %s: %d %s", method, path, code, out)
	}
	return out
}

func register(t *testing.T, b *browser, code string, auth *virtualwebauthn.Authenticator) {
	t.Helper()
	registerNamed(t, b, code, "", auth)
}

func registerNamed(t *testing.T, b *browser, code, name string, auth *virtualwebauthn.Authenticator) {
	t.Helper()
	opts, err := virtualwebauthn.ParseAttestationOptions(b.must("POST", "/auth/register/begin", `{"code":"`+code+`","name":"`+name+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	b.must("POST", "/auth/register/finish", virtualwebauthn.CreateAttestationResponse(rp, *auth, cred, *opts))
	auth.AddCredential(cred)
	auth.Options.UserHandle = b.g.st.snapshot().ID
}

func login(t *testing.T, b *browser, auth *virtualwebauthn.Authenticator) (int, string) {
	t.Helper()
	opts, err := virtualwebauthn.ParseAssertionOptions(b.must("POST", "/auth/login/begin", ""))
	if err != nil {
		t.Fatal(err)
	}
	cred := auth.Credentials[0]
	return b.do("POST", "/auth/login/finish", virtualwebauthn.CreateAssertionResponse(rp, *auth, cred, *opts))
}

const code = "0123456789abcdef0123"

func TestRegisterAndLogin(t *testing.T) {
	g := newTestGate(t, code)
	auth := virtualwebauthn.NewAuthenticator()

	first := newBrowser(t, g)
	if c, _ := first.do("GET", "/", ""); c != http.StatusSeeOther {
		t.Fatalf("logged-out GET / = %d, want redirect", c)
	}
	register(t, first, code, &auth)
	// Registering signs you in; the proxy replaces a spoofed auth header and drops cookies.
	r := httptest.NewRequest("GET", "/", nil)
	first.prepare(r)
	r.Header.Set("X-Auth-User", "evil")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if want := `user=claude cookie=""`; w.Body.String() != want {
		t.Fatalf("proxied request got %q, want %q", w.Body.String(), want)
	}

	second := newBrowser(t, g)
	if c, out := login(t, second, &auth); c != http.StatusOK {
		t.Fatalf("login: %d %s", c, out)
	}
	if out := second.must("GET", "/", ""); !strings.HasPrefix(out, "user=claude") {
		t.Fatalf("after login got %q", out)
	}

	// Signed in, a second passkey can be added without the setup code.
	auth2 := virtualwebauthn.NewAuthenticator()
	register(t, second, "", &auth2)
	if n := len(g.st.snapshot().Credentials); n != 2 {
		t.Fatalf("have %d passkeys, want 2", n)
	}

	// A logout clears the session.
	second.do("GET", "/auth/logout", "")
	if c, _ := second.do("GET", "/", ""); c != http.StatusSeeOther {
		t.Fatalf("after logout GET / = %d", c)
	}

	// Passkeys and the session key survive a restart.
	st, err := openStore(g.cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.own.Credentials) != 2 || string(st.key) != string(g.st.key) {
		t.Fatal("store didn't persist")
	}
}

func TestRegisterNeedsCode(t *testing.T) {
	b := newBrowser(t, newTestGate(t, code))
	if c, _ := b.do("POST", "/auth/register/begin", `{"code":"wrong-wrong-wrong-wrong"}`); c != http.StatusForbidden {
		t.Fatalf("wrong code: %d", c)
	}
	b = newBrowser(t, newTestGate(t, ""))
	if c, _ := b.do("POST", "/auth/register/begin", `{"code":""}`); c != http.StatusForbidden {
		t.Fatalf("no setup code configured: %d", c)
	}
	if _, err := newGate(config{Origin: origin, DataDir: t.TempDir(), SetupCode: "short"}); err == nil {
		t.Fatal("short setup code accepted")
	}
}

func TestUnknownPasskeyRefused(t *testing.T) {
	g := newTestGate(t, code)
	auth := virtualwebauthn.NewAuthenticator()
	register(t, newBrowser(t, g), code, &auth)

	// Same user handle, but a credential the gate never registered.
	other := virtualwebauthn.NewAuthenticator()
	other.Options.UserHandle = auth.Options.UserHandle
	other.AddCredential(virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2))
	if c, _ := login(t, newBrowser(t, g), &other); c != http.StatusUnauthorized {
		t.Fatalf("unknown passkey: %d", c)
	}
}

func TestCrossOriginAndBadSessions(t *testing.T) {
	g := newTestGate(t, code)
	r := httptest.NewRequest("POST", "/auth/login/begin", nil)
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin POST: %d", w.Code)
	}

	b := newBrowser(t, g)
	b.cookies[sessionCookie] = "AAAAAAAAAAA.forged"
	if c, _ := b.do("GET", "/", ""); c != http.StatusSeeOther {
		t.Fatalf("forged session: %d", c)
	}
	auth := virtualwebauthn.NewAuthenticator()
	register(t, newBrowser(t, g), code, &auth)
	cred := g.st.passkeys()[0].ID
	session := func() string {
		w := httptest.NewRecorder()
		g.startSession(w, cred)
		return w.Result().Cookies()[0].Value
	}
	b.cookies[sessionCookie] = session()
	if c, _ := b.do("GET", "/", ""); c != http.StatusOK {
		t.Fatalf("valid session: %d", c)
	}
	// Signed for one passkey, presented as another's.
	parts := strings.Split(b.cookies[sessionCookie], ".")
	b.cookies[sessionCookie] = parts[0] + ".AAAA." + parts[2]
	if c, _ := b.do("GET", "/", ""); c != http.StatusSeeOther {
		t.Fatalf("session with swapped passkey: %d", c)
	}
	// A correctly signed session whose expiry has passed.
	g.cfg.SessionTTL = -time.Minute
	b.cookies[sessionCookie] = session()
	if c, _ := b.do("GET", "/", ""); c != http.StatusSeeOther {
		t.Fatalf("expired session: %d", c)
	}
}

func TestWebsocket(t *testing.T) {
	g := newTestGate(t, code)
	srv := httptest.NewServer(g)
	defer srv.Close()
	auth := virtualwebauthn.NewAuthenticator()
	b := newBrowser(t, g)
	register(t, b, code, &auth)
	session := b.cookies[sessionCookie]

	upgrade := func(originHdr, cookie string) (string, net.Conn) {
		conn, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nOrigin: %s\r\nCookie: %s\r\n\r\n", originHdr, cookie)
		res, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		return res.Status, conn
	}
	if s, c := upgrade(origin, ""); !strings.HasPrefix(s, "401") {
		t.Fatalf("websocket without session: %s", s)
	} else {
		c.Close()
	}
	if s, c := upgrade("https://evil.example", sessionCookie+"="+session); !strings.HasPrefix(s, "403") {
		t.Fatalf("cross-origin websocket: %s", s)
	} else {
		c.Close()
	}
	s, conn := upgrade(origin, sessionCookie+"="+session)
	defer conn.Close()
	if !strings.HasPrefix(s, "101") {
		t.Fatalf("websocket: %s", s)
	}
	conn.Write([]byte("ping"))
	buf := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo through proxy: %q %v", buf, err)
	}
}

func TestManage(t *testing.T) {
	g := newTestGate(t, code)
	laptop, phone := virtualwebauthn.NewAuthenticator(), virtualwebauthn.NewAuthenticator()
	a := newBrowser(t, g)
	registerNamed(t, a, code, "  Laptop  ", &laptop)
	register(t, a, "", &phone) // signed in, no code, no name
	keys := g.st.passkeys()
	if len(keys) != 2 || keys[0].Name != "Laptop" || keys[1].Name != "Passkey 2" || keys[0].Created.IsZero() {
		t.Fatalf("passkeys after registering: %+v", keys)
	}
	laptopID, phoneID := keys[0].ID, keys[1].ID

	// The manage page needs a session; its actions too.
	if c, _ := newBrowser(t, g).do("GET", "/auth/manage", ""); c != http.StatusSeeOther {
		t.Fatalf("manage page signed out: %d", c)
	}
	if c, _ := newBrowser(t, g).do("POST", "/auth/manage/remove", `{"id":"`+laptopID+`"}`); c != http.StatusUnauthorized {
		t.Fatalf("remove signed out: %d", c)
	}
	page := a.must("GET", "/auth/manage", "")
	if !strings.Contains(page, "Laptop") || strings.Count(page, "this browser") != 1 {
		t.Fatalf("manage page:\n%s", page)
	}

	// Signing in records the last use.
	b := newBrowser(t, g)
	if c, out := login(t, b, &phone); c != http.StatusOK {
		t.Fatalf("phone login: %d %s", c, out)
	}
	if g.st.passkeys()[1].LastUsed.IsZero() {
		t.Fatal("last use not recorded")
	}

	a.must("POST", "/auth/manage/rename", `{"id":"`+phoneID+`","name":"iPhone"}`)
	if n := g.st.passkeys()[1].Name; n != "iPhone" {
		t.Fatalf("renamed to %q", n)
	}
	if c, _ := a.do("POST", "/auth/manage/rename", `{"id":"`+phoneID+`","name":"   "}`); c != http.StatusBadRequest {
		t.Fatalf("blank rename: %d", c)
	}

	// Removing the phone's passkey signs out the browser that used it, not this one.
	a.must("POST", "/auth/manage/remove", `{"id":"`+phoneID+`"}`)
	if c, _ := b.do("GET", "/", ""); c != http.StatusSeeOther {
		t.Fatalf("browser using a removed passkey: %d", c)
	}
	if c, _ := a.do("GET", "/", ""); c != http.StatusOK {
		t.Fatalf("other browser after remove: %d", c)
	}
	if c, out := a.do("POST", "/auth/manage/remove", `{"id":"`+laptopID+`"}`); c != http.StatusBadRequest || !strings.Contains(out, "only passkey") {
		t.Fatalf("removing the last passkey: %d %s", c, out)
	}

	// Signing out other browsers keeps this one.
	c := newBrowser(t, g)
	if code, out := login(t, c, &laptop); code != http.StatusOK {
		t.Fatalf("laptop login: %d %s", code, out)
	}
	a.must("POST", "/auth/manage/signout-others", "")
	if code, _ := c.do("GET", "/", ""); code != http.StatusSeeOther {
		t.Fatalf("other browser after signout-others: %d", code)
	}
	if code, _ := a.do("GET", "/", ""); code != http.StatusOK {
		t.Fatalf("this browser after signout-others: %d", code)
	}

	// Names and dates survive a restart.
	st, err := openStore(g.cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	if k := st.passkeys(); len(k) != 1 || k[0].Name != "Laptop" || k[0].LastUsed.IsZero() {
		t.Fatalf("after restart: %+v", k)
	}
}

func TestOldOwnerFileLoads(t *testing.T) {
	// owner.json as written before passkeys had names.
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "owner.json"), []byte(`{"id":"AAEC","credentials":[{"id":"AQID","publicKey":"","attestationType":"none","authenticator":{"AAGUID":null,"signCount":3}}]}`), 0o600)
	st, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	k := st.passkeys()
	if len(k) != 1 || k[0].ID != "AQID" || st.own.Credentials[0].Authenticator.SignCount != 3 {
		t.Fatalf("old file: %+v", k)
	}
	if err := st.rename("AQID", "Old key"); err != nil {
		t.Fatal(err)
	}
}

func TestFiles(t *testing.T) {
	dir := t.TempDir()
	work, secret := filepath.Join(dir, "work"), filepath.Join(dir, "secret")
	for p, body := range map[string]string{
		"work/proj/a.txt":       "hello",
		"work/proj/.git/config": "git",
		"work/page.html":        "<script>alert(1)</script>",
		"secret/creds":          "s3cret",
	} {
		os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755)
		if err := os.WriteFile(filepath.Join(dir, p), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	os.Symlink(secret, filepath.Join(work, "leak"))
	os.Symlink(filepath.Join(secret, "creds"), filepath.Join(work, "proj", "creds"))

	g := newTestGate(t, code)
	root, err := os.OpenRoot(work)
	if err != nil {
		t.Fatal(err)
	}
	g.files = root
	b := newBrowser(t, g)
	if c, _ := b.do("GET", "/files/proj/a.txt", ""); c != http.StatusSeeOther {
		t.Fatalf("logged-out GET = %d, want redirect to login", c)
	}
	auth := virtualwebauthn.NewAuthenticator()
	register(t, b, code, &auth)
	get := func(method, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		b.prepare(r)
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		return w
	}

	w := get("GET", "/files/proj/a.txt")
	if w.Code != http.StatusOK || w.Body.String() != "hello" {
		t.Fatalf("file: %d %q", w.Code, w.Body.String())
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.HasPrefix(csp, "sandbox") {
		t.Fatalf("file CSP = %q", csp)
	}
	if cd := w.Header().Get("Content-Disposition"); cd != "" {
		t.Fatalf("plain view has Content-Disposition %q", cd)
	}
	if cd := get("GET", "/files/proj/a.txt?download").Header().Get("Content-Disposition"); cd != `attachment; filename=a.txt` {
		t.Fatalf("download Content-Disposition = %q", cd)
	}
	if w := get("GET", "/files/proj"); w.Code != http.StatusFound || w.Header().Get("Location") != "/files/proj/" {
		t.Fatalf("directory without slash: %d %q", w.Code, w.Header().Get("Location"))
	}
	w = get("GET", "/files/proj/")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `href="./a.txt"`) ||
		!strings.Contains(w.Body.String(), `href="?zip"`) {
		t.Fatalf("listing: %d %s", w.Code, w.Body.String())
	}
	// Not sandboxed, or the session cookie wouldn't go with clicks on it; no scripts though.
	if csp := w.Header().Get("Content-Security-Policy"); strings.Contains(csp, "sandbox") || !strings.HasPrefix(csp, "default-src 'none'") {
		t.Fatalf("listing CSP = %q", csp)
	}

	// Nothing outside the root, whether by symlink or "..".
	for _, p := range []string{"/files/leak/creds", "/files/proj/creds", "/files/../secret/creds", "/files/leak/"} {
		if w := get("GET", p); w.Code == http.StatusOK || strings.Contains(w.Body.String(), "s3cret") {
			t.Fatalf("%s escaped the root: %d %q", p, w.Code, w.Body.String())
		}
	}
	if w := get("POST", "/files/proj/a.txt"); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d", w.Code)
	}

	w = get("GET", "/files/proj/?zip")
	if w.Code != http.StatusOK || w.Header().Get("Content-Disposition") != `attachment; filename=proj.zip` {
		t.Fatalf("zip: %d %v", w.Code, w.Header())
	}
	zr, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	if strings.Join(names, ",") != "proj/a.txt" {
		t.Fatalf("zip has %v, want just proj/a.txt (no .git, no symlinks)", names)
	}
}

func TestDav(t *testing.T) {
	dir := t.TempDir()
	work, secret := filepath.Join(dir, "work"), filepath.Join(dir, "secret")
	os.MkdirAll(filepath.Join(work, "proj"), 0o755)
	os.MkdirAll(secret, 0o755)
	os.WriteFile(filepath.Join(work, "proj", "a.txt"), []byte("hello"), 0o644)
	os.WriteFile(filepath.Join(secret, "creds"), []byte("s3cret"), 0o644)
	os.Symlink(secret, filepath.Join(work, "leak"))

	g := newTestGate(t, code)
	root, err := os.OpenRoot(work)
	if err != nil {
		t.Fatal(err)
	}
	g.files, g.dav = root, newDav(root)
	b := newBrowser(t, g)
	auth := virtualwebauthn.NewAuthenticator()
	register(t, b, code, &auth)

	dav := func(method, path, body string, set func(*http.Request)) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if set != nil {
			set(r)
		}
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		return w
	}
	// The session cookie alone isn't enough, nor is a made-up token.
	if w := dav("PROPFIND", "/dav/", "", b.prepare); w.Code != http.StatusUnauthorized ||
		w.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("cookie-only PROPFIND = %d %v", w.Code, w.Header())
	}

	var created struct{ Token string }
	json.Unmarshal([]byte(b.must("POST", "/auth/manage/token-create", `{"name":"laptop"}`)), &created)
	tok := created.Token
	if tok == "" || len(g.st.tokens()) != 1 {
		t.Fatalf("token-create gave %q, %d tokens", tok, len(g.st.tokens()))
	}
	if c, _ := newBrowser(t, g).do("POST", "/auth/manage/token-create", `{"name":"x"}`); c != http.StatusUnauthorized {
		t.Fatalf("logged-out token-create = %d", c)
	}
	bearer := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
	basic := func(r *http.Request) { r.SetBasicAuth("anyone", tok) }
	for _, bad := range []string{"nope", tok + "x", strings.SplitN(tok, ".", 2)[0] + ".AAAA"} {
		if w := dav("PROPFIND", "/dav/", "", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+bad) }); w.Code != http.StatusUnauthorized {
			t.Fatalf("token %q: %d", bad, w.Code)
		}
	}

	depth1 := func(r *http.Request) { bearer(r); r.Header.Set("Depth", "1") }
	w := dav("PROPFIND", "/dav/", "", depth1)
	if w.Code != http.StatusMultiStatus || !strings.Contains(w.Body.String(), "/dav/proj/") {
		t.Fatalf("PROPFIND: %d %s", w.Code, w.Body.String())
	}
	if w := dav("GET", "/dav/proj/a.txt", "", basic); w.Code != http.StatusOK || w.Body.String() != "hello" {
		t.Fatalf("GET with Basic: %d %q", w.Code, w.Body.String())
	} else if csp := w.Header().Get("Content-Security-Policy"); !strings.HasPrefix(csp, "sandbox") {
		t.Fatalf("GET CSP = %q", csp)
	}
	for _, step := range []struct {
		method, path, body, dest string
		want                     int
	}{
		{"MKCOL", "/dav/new/", "", "", http.StatusCreated},
		{"PUT", "/dav/new/b.txt", "written", "", http.StatusCreated},
		{"MOVE", "/dav/new/b.txt", "", "/dav/proj/c.txt", http.StatusCreated},
		{"DELETE", "/dav/new/", "", "", http.StatusNoContent},
	} {
		w := dav(step.method, step.path, step.body, func(r *http.Request) {
			bearer(r)
			if step.dest != "" {
				r.Header.Set("Destination", "http://"+r.Host+step.dest)
			}
		})
		if w.Code != step.want {
			t.Fatalf("%s %s = %d, want %d: %s", step.method, step.path, w.Code, step.want, w.Body.String())
		}
	}
	if b, err := os.ReadFile(filepath.Join(work, "proj", "c.txt")); string(b) != "written" {
		t.Fatalf("moved file: %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(work, "new")); !os.IsNotExist(err) {
		t.Fatalf("new/ still there: %v", err)
	}

	// Nothing outside the root, whether by symlink or "..".
	for _, p := range []string{"/dav/leak/creds", "/dav/../secret/creds"} {
		if w := dav("GET", p, "", bearer); w.Code == http.StatusOK || strings.Contains(w.Body.String(), "s3cret") {
			t.Fatalf("GET %s escaped the root: %d %q", p, w.Code, w.Body.String())
		}
	}
	dav("PUT", "/dav/leak/planted", "x", bearer)
	dav("DELETE", "/dav/leak/creds", "", bearer)
	if _, err := os.Stat(filepath.Join(secret, "planted")); !os.IsNotExist(err) {
		t.Fatal("PUT through a symlink wrote outside the root")
	}
	if _, err := os.Stat(filepath.Join(secret, "creds")); err != nil {
		t.Fatal("DELETE through a symlink removed a file outside the root")
	}
	if w := dav("DELETE", "/dav/", "", bearer); w.Code < 400 {
		t.Fatalf("DELETE of the root = %d", w.Code)
	}

	// Tokens outlive "sign out other browsers", and end when revoked.
	b.must("POST", "/auth/manage/signout-others", "")
	if w := dav("PROPFIND", "/dav/", "", bearer); w.Code != http.StatusMultiStatus {
		t.Fatalf("after signout-others: %d", w.Code)
	}
	if !strings.Contains(b.must("GET", "/auth/manage", ""), "laptop") {
		t.Fatal("manage page doesn't list the token")
	}
	b.must("POST", "/auth/manage/token-revoke", `{"id":"`+g.st.tokens()[0].ID+`"}`)
	if w := dav("PROPFIND", "/dav/", "", bearer); w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token: %d", w.Code)
	}
}
