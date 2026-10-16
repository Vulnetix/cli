package web

import (
	"net/http"

	"github.com/gorilla/sessions"
)

func setSession(w http.ResponseWriter, sid string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sid,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func opts() *sessions.Options {
	return &sessions.Options{Path: "/", MaxAge: 3600, HttpOnly: true, Secure: true}
}
