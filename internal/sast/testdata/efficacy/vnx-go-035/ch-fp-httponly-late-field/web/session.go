package web

import (
	"net/http"
	"time"
)

func (a *App) setSession(w http.ResponseWriter, sid string) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.cfg.CookieName,
		Value:    sid,
		Path:     "/",
		Domain:   a.cfg.CookieDomain,
		Expires:  time.Now().Add(a.cfg.SessionTTL),
		MaxAge:   int(a.cfg.SessionTTL.Seconds()),
		Secure:   a.cfg.TLS,
		SameSite: http.SameSiteStrictMode,
		// Not readable from page scripts.
		HttpOnly: true,
	})
}
