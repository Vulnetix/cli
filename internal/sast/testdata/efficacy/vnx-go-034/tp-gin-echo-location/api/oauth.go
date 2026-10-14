package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/labstack/echo/v4"
)

func authorizeGin(c *gin.Context) {
	code := issue(c)
~>	c.Redirect(http.StatusFound, c.Query("redirect_uri") + "?code=" + code)
}

func authorizeEcho(c echo.Context) error {
	ru := c.QueryParam("redirect_url")
	tok := token(c)
~>	return c.Redirect(http.StatusFound,
		ru+"#access_token="+tok)
}
