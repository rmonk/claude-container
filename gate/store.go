package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// owner is the single user the gate admits. Its WebAuthn user handle is random and
// generated once, so passkeys from an earlier data volume don't match a new one.
type owner struct {
	ID          []byte                `json:"id"`
	Credentials []webauthn.Credential `json:"credentials"`
	// Meta is keyed by credID. It's kept apart from Credentials because
	// webauthn.Credential has its own JSON decoding, which would drop added fields.
	Meta map[string]passkeyMeta `json:"meta,omitempty"`
}

type passkeyMeta struct {
	Name     string    `json:"name"`
	Created  time.Time `json:"created,omitzero"`
	LastUsed time.Time `json:"lastUsed,omitzero"`
}

// credID is how passkeys are named in owner.json's meta, in sessions and on the manage page.
func credID(id []byte) string { return base64.RawURLEncoding.EncodeToString(id) }

// passkey is a credential as the manage page shows it.
type passkey struct {
	ID string
	passkeyMeta
}

var errLastPasskey = errors.New("can't remove the only passkey; add another first")

func (o *owner) WebAuthnID() []byte                         { return o.ID }
func (o *owner) WebAuthnName() string                       { return "claude" }
func (o *owner) WebAuthnDisplayName() string                { return "claude" }
func (o *owner) WebAuthnCredentials() []webauthn.Credential { return o.Credentials }

// store keeps the owner (with its passkeys) and the session-signing key in the data
// directory, each written atomically.
type store struct {
	dir string
	mu  sync.Mutex
	own owner
	key []byte
}

func openStore(dir string) (*store, error) {
	s := &store{dir: dir}
	var err error
	if s.key, err = readOrCreate(filepath.Join(dir, "session.key"), 32); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(dir, "owner.json"))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		s.own.ID = make([]byte, 64)
		rand.Read(s.own.ID)
		if err := s.saveLocked(); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(b, &s.own); err != nil {
			return nil, err
		}
	}
	if s.own.Meta == nil {
		s.own.Meta = map[string]passkeyMeta{}
	}
	return s, nil
}

func (s *store) sessionKey() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.key
}

// rotateKey replaces the session key, which invalidates every existing session.
func (s *store) rotateKey() error {
	key := make([]byte, 32)
	rand.Read(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := writeFile(filepath.Join(s.dir, "session.key"), key); err != nil {
		return err
	}
	s.key = key
	return nil
}

func (s *store) hasCredential(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.indexLocked(id) >= 0
}

func (s *store) indexLocked(id string) int {
	for i, c := range s.own.Credentials {
		if credID(c.ID) == id {
			return i
		}
	}
	return -1
}

// passkeys lists the registered passkeys, oldest first.
func (s *store) passkeys() []passkey {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []passkey
	for _, c := range s.own.Credentials {
		id := credID(c.ID)
		out = append(out, passkey{ID: id, passkeyMeta: s.own.Meta[id]})
	}
	return out
}

func (s *store) rename(id, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.indexLocked(id) < 0 {
		return errors.New("no such passkey")
	}
	m := s.own.Meta[id]
	m.Name = name
	s.own.Meta[id] = m
	return s.saveLocked()
}

func (s *store) remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.indexLocked(id)
	if i < 0 {
		return errors.New("no such passkey")
	}
	if len(s.own.Credentials) == 1 {
		return errLastPasskey
	}
	s.own.Credentials = append(s.own.Credentials[:i], s.own.Credentials[i+1:]...)
	delete(s.own.Meta, id)
	return s.saveLocked()
}

// snapshot returns a copy of the owner that callers can use without holding the lock.
func (s *store) snapshot() *owner {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := owner{ID: s.own.ID, Credentials: append([]webauthn.Credential(nil), s.own.Credentials...)}
	return &o
}

func (s *store) hasCredentials() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.own.Credentials) > 0
}

// addCredential stores a new passkey; an empty name becomes "Passkey N".
func (s *store) addCredential(c webauthn.Credential, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.own.Credentials = append(s.own.Credentials, c)
	if name == "" {
		name = fmt.Sprintf("Passkey %d", len(s.own.Credentials))
	}
	s.own.Meta[credID(c.ID)] = passkeyMeta{Name: name, Created: time.Now().UTC()}
	return s.saveLocked()
}

// updateCredential records a credential's new sign count (and clone warning) and its
// last use after a login.
func (s *store) updateCredential(c webauthn.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := credID(c.ID)
	i := s.indexLocked(id)
	if i < 0 {
		return errors.New("credential not found")
	}
	s.own.Credentials[i].Authenticator = c.Authenticator
	m := s.own.Meta[id]
	m.LastUsed = time.Now().UTC()
	s.own.Meta[id] = m
	return s.saveLocked()
}

func (s *store) saveLocked() error {
	b, err := json.MarshalIndent(&s.own, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(s.dir, "owner.json"), b)
}

func readOrCreate(path string, n int) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err == nil && len(b) == n {
		return b, nil
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	b = make([]byte, n)
	rand.Read(b)
	return b, writeFile(path, b)
}

func writeFile(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
