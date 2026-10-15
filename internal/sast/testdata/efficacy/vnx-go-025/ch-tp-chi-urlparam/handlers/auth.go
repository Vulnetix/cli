package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func Continue(w http.ResponseWriter, r *http.Request) {
	dest := chi.URLParam(r, "dest")
~>	http.Redirect(w, r, dest, http.StatusFound)
}

func AfterLogin(w http.ResponseWriter, r *http.Request) {
	returnTo := r.PostFormValue("return_to")
	session.Save(r, w)
~>	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}
