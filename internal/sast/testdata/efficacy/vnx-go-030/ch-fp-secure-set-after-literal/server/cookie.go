package server

import "net/http"

func issue(w http.ResponseWriter, r *http.Request, token string) {
	ck := &http.Cookie{
		Name:     "auth",
		Value:    token,
		HttpOnly: true,
	}
	ck.Secure = true
	http.SetCookie(w, ck)
}
