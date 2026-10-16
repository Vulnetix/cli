package web

import "github.com/gorilla/sessions"

func Setup(store *sessions.CookieStore) {
~>	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
	}
}
