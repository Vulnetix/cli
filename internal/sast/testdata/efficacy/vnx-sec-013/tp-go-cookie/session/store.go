package session

var store = sessions.NewCookieStore([]byte(key))

func init() {
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400,
~>		HttpOnly: false,
	}
}
