package handlers

import (
	"io"
	"net/http"
	"os"
)

func Rooted(w http.ResponseWriter, r *http.Request) {
	root, err := os.OpenRoot("/srv/files")
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

func Embedded(w http.ResponseWriter, r *http.Request) {
	fsys := http.FS(os.DirFS("/srv/files"))
	http.FileServer(fsys).ServeHTTP(w, r)
}
