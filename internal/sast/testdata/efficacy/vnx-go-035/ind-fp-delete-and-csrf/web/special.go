package web

import "net/http"

func logout(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1})
}

func csrf(w http.ResponseWriter, tok string) {
	http.SetCookie(w, &http.Cookie{Name: "XSRF-TOKEN", Value: tok, Path: "/", Secure: true})
}
