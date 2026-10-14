package upload

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const dir = "/var/lib/app/uploads"

// filepath.Base strips every directory component from the client's name.
func Upload(w http.ResponseWriter, r *http.Request) {
	file, header, err := r.FormFile("file")
	if err != nil {
		return
	}
	defer file.Close()
	dst, err := os.Create(filepath.Join(dir, filepath.Base(header.Filename)))
	if err != nil {
		return
	}
	defer dst.Close()
	io.Copy(dst, file)
}

// The joined path is confined with a prefix check before the write.
func Save(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	p := filepath.Join(dir, name)
	if !strings.HasPrefix(filepath.Clean(p), dir+string(os.PathSeparator)) {
		http.Error(w, "invalid name", http.StatusBadRequest)
		return
	}
	os.WriteFile(p, []byte(r.FormValue("body")), 0o600)
}

// filepath.IsLocal rejects absolute paths and "..".
func Put(w http.ResponseWriter, r *http.Request) {
	rel := r.URL.Query().Get("path")
	if !filepath.IsLocal(rel) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	os.WriteFile(filepath.Join(dir, rel), []byte("ok"), 0o600)
}

// os.Root confines every operation to the directory it was opened on.
func Store(w http.ResponseWriter, r *http.Request) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := root.Create(r.FormValue("name"))
	if err != nil {
		return err
	}
	return f.Close()
}
