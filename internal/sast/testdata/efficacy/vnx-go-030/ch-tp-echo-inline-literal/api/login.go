package api

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func login(c echo.Context) error {
	sid := newSessionID()
~>	c.SetCookie(&http.Cookie{Name: "sid", Value: sid, Path: "/", HttpOnly: true})
	return c.NoContent(http.StatusNoContent)
}

func rememberMe(c echo.Context) error {
~>	c.SetCookie(&http.Cookie{
		Name:     "remember",
		Value:    c.Get("token").(string),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	return nil
}
