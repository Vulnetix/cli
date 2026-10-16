package server

import "net/http"

~>func handleLogin(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("username")
	pass := r.FormValue("password")
	if !checkPassword(user, pass) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: newSession(user)})
}
