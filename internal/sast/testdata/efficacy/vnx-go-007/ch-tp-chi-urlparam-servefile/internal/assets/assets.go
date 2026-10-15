package assets

import (
	"net/http"
	"path/filepath"

	"github.com/go-chi/chi/v5"
)

func Serve(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
~>	http.ServeFile(w, r, filepath.Join("static", name))
}
