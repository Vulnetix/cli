package web

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/labstack/echo/v4"
)

func AfterLogin(c *gin.Context) {
	next := c.Query("next")
~>	c.Redirect(http.StatusFound, next)
}

func Bounce(c echo.Context) error {
~>	return c.Redirect(http.StatusSeeOther, c.QueryParam("to"))
}
