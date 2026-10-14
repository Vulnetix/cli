package auth

import (
	"net/http"
	"strings"
)

type Deps struct{ SiteDomain string }

func (d *Deps) cookieFor(name, value string) *http.Cookie {
	isLocal := strings.Contains(d.SiteDomain, "localhost")
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Secure:   !isLocal,
		HttpOnly: true,
	}
}

func Login(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Secure: true, HttpOnly: true})
	c := &http.Cookie{Name: "pref", Value: "dark", Secure: r.TLS != nil}
	http.SetCookie(w, c)
}

func Later(w http.ResponseWriter, token string) {
	cookie := new(http.Cookie)
	cookie.Name = "token"
	cookie.Value = token
	cookie.Secure = true
	http.SetCookie(w, cookie)
}
