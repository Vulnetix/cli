package handlers

import (
	"net/http"
	"path/filepath"
	"strings"
)

func Upload(w http.ResponseWriter, r *http.Request) {
	f, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	defer f.Close()
~>	if strings.HasSuffix(header.Filename, ".php") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
~>	if filepath.Ext(header.Filename) == ".exe" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	save(f, header.Filename)
}
