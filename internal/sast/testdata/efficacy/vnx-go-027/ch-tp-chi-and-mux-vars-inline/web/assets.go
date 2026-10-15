package web

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/mux"
)

const root = "/srv/assets"

func Theme(w http.ResponseWriter, r *http.Request) {
	theme := chi.URLParam(r, "theme")
~>	css, err := os.ReadFile(filepath.Join(root, "themes", theme+".css"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Write(css)
}

func Asset(w http.ResponseWriter, r *http.Request) {
~>	http.ServeFile(w, r, filepath.Join(root, mux.Vars(r)["path"]))
}
