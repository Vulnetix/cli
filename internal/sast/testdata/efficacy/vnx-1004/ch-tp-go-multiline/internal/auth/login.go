package auth

import (
	"net/http"
	"time"
)

const sessionCookie = "session_id"

func setSession(w http.ResponseWriter, sid string) {
~>	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sid,
		Path:     "/",
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(12 * time.Hour),
	})
}
