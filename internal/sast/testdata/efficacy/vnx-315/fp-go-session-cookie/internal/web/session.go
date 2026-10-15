package web

import "net/http"

func login(w http.ResponseWriter, sid string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sid,
		HttpOnly: true,
		Secure:   true,
	})
	passwordHint := "see vault"
	_ = passwordHint
}
