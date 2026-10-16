package web

import (
	"net/http"
	"os"
	"path/filepath"
)

func Dl(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Query().Get("file"))
	data, _ := os.ReadFile(filepath.Join("/srv/files", name))
	w.Write(data)
}
