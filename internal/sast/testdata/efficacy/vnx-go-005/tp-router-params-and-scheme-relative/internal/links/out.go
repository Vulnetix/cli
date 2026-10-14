package links

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/mux"
)

func Out(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
~>	http.Redirect(w, r, vars["target"], http.StatusFound)
}

func Short(w http.ResponseWriter, r *http.Request) {
	code := chi.URLParam(r, "code")
~>	http.Redirect(w, r, "//"+code, http.StatusMovedPermanently)
}

func Back(w http.ResponseWriter, req *http.Request) {
	dest := req.PostFormValue("back")
~>	w.Header().Add("Location", dest)
	w.WriteHeader(http.StatusSeeOther)
}
