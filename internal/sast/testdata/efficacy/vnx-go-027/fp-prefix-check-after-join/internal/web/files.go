package web

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const base = "/srv/files"

func Get(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	full := filepath.Join(base, name)
	if !strings.HasPrefix(full, base+string(os.PathSeparator)) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	data, err := os.ReadFile(full)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Write(data)
}

func Rm(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	if strings.Contains(name, "..") || strings.ContainsAny(name, `/\`) {
		http.Error(w, "bad name", http.StatusBadRequest)
		return
	}
	os.Remove(filepath.Join(base, name))
}
