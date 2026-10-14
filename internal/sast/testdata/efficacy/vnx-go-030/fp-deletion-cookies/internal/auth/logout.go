package auth

import (
	"net/http"
	"time"
)

func Logout(w http.ResponseWriter, names []string) {
	for _, name := range names {
		http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1})
		cookie := &http.Cookie{
			Name:    name,
			Value:   "",
			Expires: time.Unix(0, 0),
		}
		http.SetCookie(w, cookie)
	}
}
