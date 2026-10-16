package web

import "net/http"

func Logout(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1})
}

func Attach(req *http.Request, v string) {
	req.AddCookie(&http.Cookie{Name: "sid", Value: v})
}
