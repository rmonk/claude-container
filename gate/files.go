package main

import (
	"archive/zip"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
)

// /files/ is a read-only view of GATE_FILES (the claude container's ~/work), for
// reviewing and downloading what's been made there. It's opened as an os.Root, so ".."
// and symlinks that lead outside it fail. The files are untrusted content served from the
// terminal's origin, so every response is sandboxed: no scripts, and an opaque origin that
// the websocket check (sameOrigin) refuses.
const filesCSP = "sandbox allow-downloads; default-src 'none'; img-src 'self' data:; " +
	"style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// Left out of ?zip archives; they're large and not what's being reviewed.
var zipSkip = map[string]bool{".git": true, "node_modules": true}

type fileEntry struct {
	Name, Href, Size, Modified string
	Dir                        bool
}

func (g *gate) serveFiles(w http.ResponseWriter, r *http.Request) {
	if g.files == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "read-only", http.StatusMethodNotAllowed)
		return
	}
	h := w.Header()
	h.Set("Content-Security-Policy", filesCSP)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")

	name := strings.Trim(strings.TrimPrefix(r.URL.Path, "/files"), "/")
	if name == "" {
		name = "."
	}
	if !fs.ValidPath(name) {
		http.NotFound(w, r)
		return
	}
	fsys := g.files.FS()
	info, err := fs.Stat(fsys, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	slash := strings.HasSuffix(r.URL.Path, "/")
	switch {
	case info.IsDir() && !slash:
		redirect(w, r, r.URL.EscapedPath()+"/")
	case !info.IsDir() && slash:
		redirect(w, r, strings.TrimSuffix(r.URL.EscapedPath(), "/"))
	case info.IsDir() && r.URL.Query().Has("zip"):
		zipDir(w, fsys, name)
	case info.IsDir():
		listDir(w, fsys, name)
	default:
		f, err := fsys.Open(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		if r.URL.Query().Has("download") {
			attachment(w, path.Base(name))
		}
		http.ServeContent(w, r, path.Base(name), info.ModTime(), f.(io.ReadSeeker))
	}
}

func redirect(w http.ResponseWriter, r *http.Request, to string) {
	if r.URL.RawQuery != "" {
		to += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, to, http.StatusFound)
}

func attachment(w http.ResponseWriter, filename string) {
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filename}))
}

func listDir(w http.ResponseWriter, fsys fs.FS, dir string) {
	des, err := fs.ReadDir(fsys, dir)
	if err != nil {
		http.Error(w, "can't read this directory", http.StatusInternalServerError)
		return
	}
	entries := make([]fileEntry, 0, len(des))
	for _, d := range des {
		// "./" so a name like "x:y" isn't read as a URL scheme.
		e := fileEntry{Name: d.Name(), Href: "./" + url.PathEscape(d.Name()), Dir: d.IsDir()}
		if e.Dir {
			e.Name += "/"
			e.Href += "/"
		} else if info, err := d.Info(); err == nil {
			e.Size = humanSize(info.Size())
			e.Modified = info.ModTime().Format("2 Jan 2006 15:04")
		}
		entries = append(entries, e)
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Dir && !entries[j].Dir })
	shown := "work/"
	if dir != "." {
		shown += dir + "/"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.ExecuteTemplate(w, "files.html", map[string]any{
		"Path": shown, "Top": dir == ".", "Entries": entries,
	})
}

// zipDir streams dir as <name>.zip, with everything inside a folder of that name. Only
// regular files go in: symlinks are skipped, wherever they point.
func zipDir(w http.ResponseWriter, fsys fs.FS, dir string) {
	base := path.Base(dir)
	if dir == "." {
		base = "work"
	}
	w.Header().Set("Content-Type", "application/zip")
	attachment(w, base+".zip")
	zw := zip.NewWriter(w)
	err := fs.WalkDir(fsys, dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// Unreadable: leave it out rather than cut the archive short.
			log.Printf("gate: files: zip %s: %v", p, err)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if p != dir && zipSkip[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		hdr, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		rel := p
		if dir != "." {
			rel = strings.TrimPrefix(p, dir+"/")
		}
		hdr.Name, hdr.Method = base+"/"+rel, zip.Deflate
		f, err := fsys.Open(p)
		if err != nil {
			log.Printf("gate: files: zip %s: %v", p, err)
			return nil
		}
		defer f.Close()
		out, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, f)
		return err
	})
	if err != nil {
		// The response has started, so all we can do is stop; the archive will be invalid.
		log.Printf("gate: files: zip %s: %v", dir, err)
		return
	}
	zw.Close()
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
