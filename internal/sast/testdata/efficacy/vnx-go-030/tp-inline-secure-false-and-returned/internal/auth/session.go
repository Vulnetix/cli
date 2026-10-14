package auth

import (
	"net/http"
	"time"
)

func Login(w http.ResponseWriter, token string) {
~>	http.SetCookie(w, &http.Cookie{Name: "session", Value: token, HttpOnly: true, Secure: false})
}

// The caller hands this to http.SetCookie.
func sessionCookie(v string) *http.Cookie {
~>	return &http.Cookie{
		Name:     "sid",
		Value:    v,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}
