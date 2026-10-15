package auth

import "net/http"

func sessionCookie(name, value string) *http.Cookie {
	ck := &http.Cookie{Name: name, Value: value, Path: "/"}
	ck.Secure = true
	ck.HttpOnly = true
	ck.SameSite = http.SameSiteLaxMode
	return ck
}

func (h *Handler) set(w http.ResponseWriter, v string) {
	c := new(http.Cookie)
	c.Name, c.Value = "sid", v
	c.HttpOnly = true
	http.SetCookie(w, c)
}
