package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gofiber/fiber/v2"
)

func ginLogin(c *gin.Context) {
	tok := issue(c)
~>	c.SetCookie("session", tok, 3600, "/", "", true, false)
}

func fiberLogin(c *fiber.Ctx) error {
~>	c.Cookie(&fiber.Cookie{Name: "sid", Value: newSID(), Secure: true, HTTPOnly: false})
	return nil
}

func plain(w http.ResponseWriter, sid string) {
~>	http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid, HttpOnly: false})
}

func relax(ck *http.Cookie) {
~>	ck.HttpOnly = false
}
