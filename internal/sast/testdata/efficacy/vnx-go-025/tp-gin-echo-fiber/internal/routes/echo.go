package routes

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func Bounce(c echo.Context) error {
	target := c.QueryParam("url")
	audit(target)
~>	return c.Redirect(http.StatusMovedPermanently, target)
}

func audit(string) {}
