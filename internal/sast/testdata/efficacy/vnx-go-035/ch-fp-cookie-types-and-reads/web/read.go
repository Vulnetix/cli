package web

import (
	"errors"
	"net/http"
)

var errNoSession = errors.New("no session")

func sessionID(r *http.Request) (string, error) {
	ck, err := r.Cookie("sid")
	if err != nil {
		return "", errNoSession
	}
	return ck.Value, nil
}

func copyCookies(dst *http.Request, src []*http.Cookie) {
	for _, c := range src {
		dst.AddCookie(c)
	}
}

// See http.Cookie{HttpOnly: true} for how the server writes it.
const hint = "set http.Cookie{Name: \"sid\"} with HttpOnly"
