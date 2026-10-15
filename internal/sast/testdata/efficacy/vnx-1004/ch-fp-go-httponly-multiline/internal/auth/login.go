package auth

import "net/http"

func setSession(w http.ResponseWriter, sid string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sid,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
	})
}

func setTheme(w http.ResponseWriter, theme string) {
	http.SetCookie(w, &http.Cookie{Name: "theme", Value: theme, Path: "/"})
}
