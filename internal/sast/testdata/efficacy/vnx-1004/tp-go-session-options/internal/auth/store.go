package auth

import (
	"net/http"

	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte("k"))

func Save(w http.ResponseWriter, r *http.Request) error {
	s, _ := store.Get(r, "app")
	s.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
~>		HttpOnly: false,
	}
	return s.Save(r, w)
}
