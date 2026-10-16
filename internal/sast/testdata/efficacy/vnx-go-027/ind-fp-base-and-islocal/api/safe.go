package api

import (
	"net/http"
	"os"
	"path/filepath"
)

func A(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Query().Get("name"))
	data, _ := os.ReadFile(filepath.Join("./configs", name))
	w.Write(data)
}

func B(w http.ResponseWriter, r *http.Request) {
	rel := r.FormValue("p")
	if !filepath.IsLocal(rel) {
		http.Error(w, "bad", 400)
		return
	}
	data, _ := os.ReadFile(filepath.Join("/srv/data", rel))
	w.Write(data)
}
