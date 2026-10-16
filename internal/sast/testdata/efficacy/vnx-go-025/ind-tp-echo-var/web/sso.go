package web

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func Callback(c echo.Context) error {
	next := c.QueryParam("next")
	session := c.Get("session")
	_ = session
~>	return c.Redirect(http.StatusSeeOther, next)
}
