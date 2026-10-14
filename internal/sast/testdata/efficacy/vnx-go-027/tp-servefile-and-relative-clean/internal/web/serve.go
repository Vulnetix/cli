package web

import (
	"net/http"
	"os"
	"path/filepath"
)

const base = "/var/lib/app/docs"

func Doc(w http.ResponseWriter, r *http.Request) {
~>	http.ServeFile(w, r, filepath.Join(base, r.FormValue("path")))
}

// filepath.Clean of a relative path keeps its leading "../".
func Open(w http.ResponseWriter, r *http.Request) {
	name := filepath.Clean(r.FormValue("f"))
~>	f, err := os.Open(filepath.Join(base, name))
	if err != nil {
		return
	}
	defer f.Close()
}

// A handler mounted without a ServeMux sees the raw request path.
func Raw(w http.ResponseWriter, r *http.Request) {
~>	f, err := os.Open(filepath.Join(base, r.URL.Path))
	if err != nil {
		return
	}
	defer f.Close()
}
