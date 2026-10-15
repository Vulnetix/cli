package admin

import (
	"net/http"
	"os"

	"github.com/labstack/echo/v4"
)

func Env(c echo.Context) error {
~>	return c.JSON(http.StatusOK, os.Environ())
}
