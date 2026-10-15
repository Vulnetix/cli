package web

import "net/http"

func setSession(w http.ResponseWriter, sid string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sid,
~>		HttpOnly: false,
~>		Secure:   false,
	})
}

func login(c *gin.Context, token string) {
~>	c.SetCookie("auth_token", token, 3600, "/", "", false, true)
}
