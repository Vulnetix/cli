package util

import "net/http"

func SetCookie(w http.ResponseWriter, name, value string) {
~>	cookie := http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)
}
