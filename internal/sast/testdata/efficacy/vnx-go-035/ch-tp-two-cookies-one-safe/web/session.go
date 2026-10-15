package web

import "net/http"

func writeSession(w http.ResponseWriter, sid, csrfSeed string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
	})
~>	http.SetCookie(w, &http.Cookie{
		Name:   "remember_me",
		Value:  sid,
		Path:   "/",
		Secure: true,
		MaxAge: 2592000,
	})
}
