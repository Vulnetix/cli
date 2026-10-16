package web

import (
	"net/http"
)

func Logout(w http.ResponseWriter, r *http.Request) {
	clearSession(w, r)
	target := r.FormValue("continue")
~>	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusFound)
}
