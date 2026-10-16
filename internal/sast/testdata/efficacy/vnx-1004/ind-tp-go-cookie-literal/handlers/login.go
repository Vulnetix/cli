package handlers

import (
	"net/http"
	"time"
)

func Login(w http.ResponseWriter, r *http.Request) {
	token := issueToken(r.FormValue("user"))
~>	http.SetCookie(w, &http.Cookie{Name: "auth_token", Value: token, Path: "/", Secure: true, Expires: time.Now().Add(time.Hour)})
	w.WriteHeader(http.StatusNoContent)
}
