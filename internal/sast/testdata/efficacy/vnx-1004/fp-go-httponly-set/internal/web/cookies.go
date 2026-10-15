package web

import (
	"net/http"
	"time"
)

func issue(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		HttpOnly: true,
		Secure:   true,
	})
}

func later(w http.ResponseWriter, id string) {
	c := &http.Cookie{Name: "session", Value: id}
	c.HttpOnly = true
	http.SetCookie(w, c)
}

func theme(w http.ResponseWriter, v string) {
	http.SetCookie(w, &http.Cookie{Name: "theme", Value: v})
}

func csrf(w http.ResponseWriter, v string) {
	http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: v, HttpOnly: false})
}

func logout(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Expires: time.Unix(0, 0)})
}

// SetCookie lets the caller decide.
func SetCookie(w http.ResponseWriter, name, value string, httpOnly bool) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, HttpOnly: httpOnly})
}
