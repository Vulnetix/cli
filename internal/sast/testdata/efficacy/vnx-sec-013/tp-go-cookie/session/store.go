package session

var store = sessions.NewCookieStore([]byte(key))

func init() {
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400,
		// Reported by VNX-1004 (a cookie without HttpOnly), not by this rule.
		HttpOnly: false,
	}
}
