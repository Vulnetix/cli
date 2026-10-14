package web

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gofiber/fiber/v2"
	"github.com/gorilla/sessions"
)

func setSession(w http.ResponseWriter, sid string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sid,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func fromConfig(w http.ResponseWriter, sid string) {
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid, HttpOnly: cfg.HTTPOnlyCookies})
}

func viaNew(w http.ResponseWriter, sid string) {
	ck := new(http.Cookie)
	ck.Name = "sid"
	ck.Value = sid
	ck.HttpOnly = true
	http.SetCookie(w, ck)
}

func ginLogin(c *gin.Context) {
	c.SetCookie("session", issue(c), 3600, "/", "", true, true)
}

func fiberLogin(c *fiber.Ctx) error {
	c.Cookie(&fiber.Cookie{Name: "sid", Value: newSID(), HTTPOnly: true})
	return nil
}

func configure(store *sessions.CookieStore) {
	store.Options = &sessions.Options{Path: "/", HttpOnly: true, Secure: true}
}
