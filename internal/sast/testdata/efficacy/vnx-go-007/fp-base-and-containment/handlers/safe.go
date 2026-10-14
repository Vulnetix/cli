package handlers

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const root = "/srv/files"

func ByBase(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.FormValue("file"))
	data, err := os.ReadFile(filepath.Join(root, name))
	if err == nil {
		w.Write(data)
	}
}

func Contained(w http.ResponseWriter, r *http.Request) {
	p := filepath.Join(root, r.URL.Query().Get("p"))
	if !strings.HasPrefix(filepath.Clean(p), root+string(os.PathSeparator)) {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	data, _ := os.ReadFile(p)
	w.Write(data)
}

func Local(w http.ResponseWriter, r *http.Request) {
	rel := r.FormValue("rel")
	if !filepath.IsLocal(rel) {
		return
	}
	f, _ := os.Open(filepath.Join(root, rel))
	defer f.Close()
}

func Numbered(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(r.FormValue("page"))
	if err != nil {
		return
	}
	data, _ := os.ReadFile(filepath.Join(root, "pages", strconv.Itoa(n)+".html"))
	w.Write(data)
}

func Sanitised(w http.ResponseWriter, r *http.Request) {
	name, err := sanitizeName(r.FormValue("n"))
	if err != nil {
		return
	}
	data, _ := os.ReadFile(filepath.Join(root, name))
	w.Write(data)
}

func sanitizeName(s string) (string, error) { return s, nil }
