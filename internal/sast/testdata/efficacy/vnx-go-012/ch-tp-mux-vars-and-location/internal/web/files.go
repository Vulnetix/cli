package web

import (
	"net/http"

	"github.com/gorilla/mux"
)

func Download(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]
~>	w.Header().Set("Content-Disposition", "attachment; filename=\""+name+"\"")
	http.ServeFile(w, r, "/srv/files/report.pdf")
}

func Continue(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
~>	w.Header().Set("Location", next)
	w.WriteHeader(http.StatusFound)
}

func Tag(w http.ResponseWriter, r *http.Request) {
~>	w.Header().Add("X-Resource-Id", mux.Vars(r)["id"])
	w.WriteHeader(http.StatusNoContent)
}
