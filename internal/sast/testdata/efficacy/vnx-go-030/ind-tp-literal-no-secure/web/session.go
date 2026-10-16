package web

import "net/http"

func SetSession(w http.ResponseWriter, value string) {
~>	cookie := http.Cookie{
		Name:     "sid",
		Value:    value,
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)
}
