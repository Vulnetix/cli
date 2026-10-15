package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func Save(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" || strings.Contains(name, "..") || strings.ContainsAny(name, `/\`) {
		http.Error(w, "bad name", http.StatusBadRequest)
		return
	}
	os.WriteFile(filepath.Join("/srv/files", name), []byte("x"), 0o600)
}

func SaveRooted(w http.ResponseWriter, r *http.Request) {
	root, err := os.OpenRoot("/srv/files")
	if err != nil {
		return
	}
	defer root.Close()
	f, err := root.Create(r.FormValue("name"))
	if err == nil {
		f.Close()
	}
}
