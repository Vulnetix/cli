package web

import (
	"net/http"
	"time"
)

const sessionCookie = "app_session"

func issue(w http.ResponseWriter, token string) {
~>	http.SetCookie(w, &http.Cookie{
		Name:    "auth_token",
		Value:   token,
		Path:    "/",
		Expires: time.Now().Add(24 * time.Hour),
	})
}

func issueSession(w http.ResponseWriter, id string) {
~>	c := http.Cookie{Name: sessionCookie, Value: id, Secure: true}
	http.SetCookie(w, &c)
}

func remember(w http.ResponseWriter, v string) {
~>	http.SetCookie(w, &http.Cookie{
		Name:     "remember_me",
		Value:    v,
		HttpOnly: false,
	})
}
