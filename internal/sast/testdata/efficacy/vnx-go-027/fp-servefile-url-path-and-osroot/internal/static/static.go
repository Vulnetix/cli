package static

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const dir = "/srv/static"

// http.ServeFile itself rejects any request whose URL path has a ".." element.
func Serve(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, filepath.Join(dir, r.URL.Path))
}

// os.Root confines every open to the directory.
func Rooted(w http.ResponseWriter, r *http.Request) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return
	}
	defer root.Close()
	f, err := root.Open(r.FormValue("name"))
	if err != nil {
		return
	}
	defer f.Close()
	io.Copy(w, f)
}
