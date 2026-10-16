package web

import (
	"net/http"
	"time"
)

func Remember(w http.ResponseWriter, tok string) {
~>	http.SetCookie(w, &http.Cookie{
		Name:     "remember",
		Value:    tok,
		Expires:  time.Now().Add(30 * 24 * time.Hour),
		Secure:   false,
		HttpOnly: true,
	})
}
