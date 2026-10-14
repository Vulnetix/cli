package web

import (
	"net/http"

	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte(key))

func init() {
~>	store.Options = &sessions.Options{
		Path:   "/",
		MaxAge: 86400,
		Secure: true,
	}
}

func remember(w http.ResponseWriter, token string) {
~>	ck := new(http.Cookie)
	ck.Name = "remember_me"
	ck.Value = token
	ck.Secure = true
	http.SetCookie(w, ck)
}
