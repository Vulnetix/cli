package web

import "net/http"

func writeSession(w http.ResponseWriter, sid string) {
	c := &http.Cookie{Name: "session", Value: sid, Path: "/"}
	c.Secure = true
	c.HttpOnly = true
	http.SetCookie(w, c)
}
