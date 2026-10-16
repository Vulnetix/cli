package server

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

~>func Login(c echo.Context) error {
	u := c.FormValue("user")
	if u == "" {
		return c.NoContent(http.StatusBadRequest)
	}
	return c.JSON(http.StatusOK, map[string]string{"token": "x"})
}
