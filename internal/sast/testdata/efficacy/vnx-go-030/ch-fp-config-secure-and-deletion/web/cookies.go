package web

import (
	"net/http"
	"time"
)

func setSession(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func logout(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:    "session",
		Value:   "",
		Path:    "/",
		MaxAge:  -1,
		Expires: time.Unix(0, 0),
	})
}
