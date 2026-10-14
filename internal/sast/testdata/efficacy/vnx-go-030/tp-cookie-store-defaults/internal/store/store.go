package store

import "github.com/gorilla/sessions"

// NewCookieStore's default Options leave Secure off, and nothing here sets it.
~>var Store = sessions.NewCookieStore([]byte("signing-key-from-env"))
