package web

import "net/http"

func Prefs(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "role", Value: "viewer", HttpOnly: true})
	c, err := r.Cookie("locale")
	if err == nil && c.Value == "fr" {
		w.Header().Set("Content-Language", "fr")
	}
}
