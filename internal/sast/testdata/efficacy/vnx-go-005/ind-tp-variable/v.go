package web

import "net/http"

func Login(w http.ResponseWriter, r *http.Request) {
	next := r.FormValue("redirect_to")
	// ... authenticate
~>	http.Redirect(w, r, next, http.StatusSeeOther)
}
