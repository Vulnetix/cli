package web

import "net/http"

func Dismiss(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "pin_banner_dismissed", Value: "1", Path: "/"})
	http.SetCookie(w, &http.Cookie{Name: "lang", Value: r.URL.Query().Get("lang")})
}
