package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func ServeFile(w http.ResponseWriter, r *http.Request) {
~>	if strings.Contains(r.URL.RawQuery, "..") {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	name := r.URL.Query().Get("name")
	data, err := os.ReadFile(filepath.Join("/srv/files", name))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Write(data)
}
