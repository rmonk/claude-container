package main

import (
	"context"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"

	"golang.org/x/net/webdav"
)

// /dav/ is a read-write WebDAV view of GATE_FILES, for mounting ~/work with rclone (or
// Finder, Windows, davfs2). Those clients can't do passkeys, so it takes only the tokens
// made on /auth/manage, never the session cookie. Like /files/, it goes through the
// os.Root, so ".." and symlinks that lead outside ~/work fail.

// rootFS is a webdav.FileSystem over an os.Root. webdav.Dir isn't used because it works
// on plain paths and follows symlinks wherever they point.
type rootFS struct{ root *os.Root }

// rel turns WebDAV's "/a/b" into the root-relative "a/b" ("." for the top).
func rel(name string) (string, error) {
	name = strings.Trim(name, "/")
	if name == "" {
		return ".", nil
	}
	if !fs.ValidPath(name) {
		return "", fs.ErrNotExist
	}
	return name, nil
}

func (r rootFS) Mkdir(_ context.Context, name string, perm os.FileMode) error {
	name, err := rel(name)
	if err != nil {
		return err
	}
	return r.root.Mkdir(name, perm)
}

func (r rootFS) OpenFile(_ context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	name, err := rel(name)
	if err != nil {
		return nil, err
	}
	f, err := r.root.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (r rootFS) RemoveAll(_ context.Context, name string) error {
	name, err := rel(name)
	if err != nil {
		return err
	}
	if name == "." {
		return fs.ErrPermission
	}
	return r.root.RemoveAll(name)
}

func (r rootFS) Rename(_ context.Context, oldName, newName string) error {
	oldName, err := rel(oldName)
	if err != nil {
		return err
	}
	if newName, err = rel(newName); err != nil {
		return err
	}
	if oldName == "." || newName == "." {
		return fs.ErrPermission
	}
	return r.root.Rename(oldName, newName)
}

func (r rootFS) Stat(_ context.Context, name string) (os.FileInfo, error) {
	name, err := rel(name)
	if err != nil {
		return nil, err
	}
	return r.root.Stat(name)
}

func newDav(root *os.Root) *webdav.Handler {
	return &webdav.Handler{
		Prefix:     "/dav",
		FileSystem: rootFS{root},
		LockSystem: webdav.NewMemLS(),
		Logger: func(r *http.Request, err error) {
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				log.Printf("gate: dav: %s %s: %v", r.Method, r.URL.Path, err)
			}
		},
	}
}

func (g *gate) serveDav(w http.ResponseWriter, r *http.Request) {
	if g.dav == nil {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	// A browser that was given the token through a Basic-auth prompt sends it by itself,
	// so files opened here are sandboxed exactly as on /files/.
	h.Set("Content-Security-Policy", filesCSP)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	if !g.st.checkToken(davToken(r)) {
		if r.Header.Get("Authorization") != "" {
			log.Printf("gate: dav: bad token from %s", r.RemoteAddr)
		}
		h.Set("WWW-Authenticate", `Basic realm="claude work"`)
		http.Error(w, "a token from /auth/manage is required", http.StatusUnauthorized)
		return
	}
	g.dav.ServeHTTP(w, r)
}

// davToken takes the token from "Authorization: Bearer <token>", or from Basic auth's
// password (the user name is ignored) for clients that only do Basic.
func davToken(r *http.Request) string {
	if t, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		return strings.TrimSpace(t)
	}
	if _, pass, ok := r.BasicAuth(); ok {
		return pass
	}
	return ""
}
