package web

import "net/http"

func rememberLogin(w http.ResponseWriter, r *http.Request) {
	pw := r.FormValue("password")
~>	http.SetCookie(w, &http.Cookie{Name: "password", Value: pw, Path: "/", HttpOnly: true})
	http.Redirect(w, r, "/", http.StatusFound)
}
