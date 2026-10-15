package web

func setSession(w http.ResponseWriter, sid string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sid,
		HttpOnly: true,
		Secure:   true,
	})
	c.SetCookie("auth_token", token, 3600, "/", "", true, true)
}
