package web

import "net/http"

~>func handleSignIn(w http.ResponseWriter, r *http.Request) {
	if !authenticate(r.PostFormValue("email"), r.PostFormValue("password")) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
