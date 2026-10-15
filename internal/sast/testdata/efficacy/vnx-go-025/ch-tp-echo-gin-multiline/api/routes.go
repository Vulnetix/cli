package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/labstack/echo/v4"
)

func oauthCallback(c *gin.Context) {
	redirectURI := c.DefaultQuery("redirect_uri", "/")
~>	c.Redirect(
		http.StatusTemporaryRedirect,
		redirectURI,
	)
}

func shortLink(c echo.Context) error {
~>	return c.Redirect(http.StatusMovedPermanently, c.FormValue("u"))
}
