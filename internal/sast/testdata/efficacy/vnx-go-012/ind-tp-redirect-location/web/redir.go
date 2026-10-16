package web

import "net/http"

func AfterLogin(w http.ResponseWriter, r *http.Request) {
	next := r.FormValue("next")
	if next == "" {
		next = "/home"
	}
~>	w.Header().Set("Location", next)
	w.WriteHeader(http.StatusFound)
}
