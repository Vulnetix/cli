package web

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func Download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	f, err := os.Open(filepath.Join("/srv/public", name))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	io.Copy(w, f)
}
