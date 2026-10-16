package web

import "github.com/gorilla/sessions"

func newStore(key []byte) *sessions.CookieStore {
	store := sessions.NewCookieStore(key)
~>	store.Options = &sessions.Options{Path: "/", MaxAge: 86400, Secure: true}
	return store
}
