package handlers

import "net/http"

func Safe(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
	})
}

func Safe2(w http.ResponseWriter, token string) {
	c := &http.Cookie{Name: "auth_token", Value: token}
	c.HttpOnly = true
	http.SetCookie(w, c)
}
