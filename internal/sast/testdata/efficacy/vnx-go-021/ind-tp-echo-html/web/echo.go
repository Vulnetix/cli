package web

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func Greet(c echo.Context) error {
	name := c.QueryParam("name")
~>	return c.HTML(http.StatusOK, "<p>Hello "+name+"</p>")
}
