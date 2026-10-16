package web

import "net/http"

func setSession(w http.ResponseWriter, sid string) {
~>	http.SetCookie(w, &http.Cookie{Name: "session", Value: sid, Path: "/", Secure: true, MaxAge: 3600})
}
