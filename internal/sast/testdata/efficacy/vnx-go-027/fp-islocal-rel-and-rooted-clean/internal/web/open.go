package web

import (
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const root = "/srv/site"

func Local(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	if !filepath.IsLocal(name) {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	f, _ := os.Open(filepath.Join(root, name))
	defer f.Close()
}

func Relative(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("p")
	full := filepath.Join(root, name)
	rel, err := filepath.Rel(root, full)
	if err != nil || strings.HasPrefix(rel, "..") {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	os.ReadFile(full)
}

// Cleaning a rooted path removes every "..".
func Rooted(w http.ResponseWriter, r *http.Request) {
	p := path.Clean("/" + r.URL.Query().Get("p"))
	os.ReadFile(filepath.Join(root, p))
}

func Checked(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("doc")
	if err := validateName(name); err != nil {
		return
	}
	os.ReadFile(filepath.Join(root, name))
}

func validateName(string) error { return nil }
