package auth

import "net/http"

func Login(w http.ResponseWriter, r *http.Request) {
	if !valid(r.FormValue("user"), r.FormValue("password")) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
