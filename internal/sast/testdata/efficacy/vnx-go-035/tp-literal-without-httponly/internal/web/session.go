package web

import (
	"net/http"
	"time"
)

func setSession(w http.ResponseWriter, sid string) {
~>	http.SetCookie(w, &http.Cookie{
		Name:    "session",
		Value:   sid,
		Secure:  true,
		Expires: time.Now().Add(12 * time.Hour),
	})
}

func setUID(w http.ResponseWriter, uid string) {
~>	cookie := http.Cookie{
		Name:  "Uid",
		Value: uid,
	}
	http.SetCookie(w, &cookie)
}

func authCookie(tok string) *http.Cookie {
~>	return &http.Cookie{Name: "auth", Value: tok, Path: "/", Secure: true, SameSite: http.SameSiteLaxMode}
}
