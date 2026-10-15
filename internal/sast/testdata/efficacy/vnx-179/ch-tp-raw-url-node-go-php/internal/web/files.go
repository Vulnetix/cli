package web

import (
	"net/http"
	"path/filepath"
	"strings"
)

func Files(w http.ResponseWriter, r *http.Request) {
~>	if strings.Contains(r.URL.RawQuery, "..") {
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
	name := r.URL.Query().Get("name")
	http.ServeFile(w, r, filepath.Join("/srv/files", name))
}
