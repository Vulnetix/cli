package web

import "net/http"

func A(w http.ResponseWriter, v string) {
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: v, Path: "/", HttpOnly: true, Secure: true})
}

func B(w http.ResponseWriter, r *http.Request, v string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    v,
		HttpOnly: true,
		Secure:   r.TLS != nil,
	})
}
