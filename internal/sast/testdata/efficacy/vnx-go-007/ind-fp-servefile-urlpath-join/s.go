package web

import (
	"net/http"
	"path/filepath"
)

func Serve(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, filepath.Join("static", r.URL.Path))
}
