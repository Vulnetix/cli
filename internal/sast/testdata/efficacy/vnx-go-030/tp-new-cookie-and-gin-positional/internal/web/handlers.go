package web

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/labstack/echo/v4"
)

func EchoLogin(c echo.Context) error {
~>	cookie := new(http.Cookie)
	cookie.Name = "token"
	cookie.Value = issue()
	cookie.HttpOnly = true
	c.SetCookie(cookie)
	return c.NoContent(http.StatusOK)
}

func GinLogin(c *gin.Context) {
~>	c.SetCookie("session", issue(), 3600, "/", "", false, true)
}

func issue() string { return "t" }
