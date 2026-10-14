package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/mux"
)

func Create(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
~>	w.Header().Set("Location", "/items/"+id)
	w.WriteHeader(http.StatusCreated)
}

func Slug(w http.ResponseWriter, r *http.Request) {
~>	w.Header().Set("X-Slug", chi.URLParam(r, "slug"))
	trace := r.FormValue("trace")
~>	w.Header()["X-Trace"] = []string{trace}
~>	w.Header().Add("X-Name", r.PathValue("name"))
}
