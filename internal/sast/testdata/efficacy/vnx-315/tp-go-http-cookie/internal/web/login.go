package web

import "net/http"

func remember(w http.ResponseWriter, r *http.Request) {
	password := r.FormValue("password")
~>	http.SetCookie(w, &http.Cookie{
		Name:     "password",
		Value:    password,
		HttpOnly: true,
	})
~>	http.SetCookie(w, &http.Cookie{Name: "remember", Value: r.FormValue("user") + ":" + password})
}
