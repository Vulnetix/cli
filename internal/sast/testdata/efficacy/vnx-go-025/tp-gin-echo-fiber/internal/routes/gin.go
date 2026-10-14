package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func OAuthDone(c *gin.Context) {
~>	c.Redirect(http.StatusFound, c.Query("redirect_uri"))
}

func Jump(c *gin.Context) {
	dest := c.DefaultQuery("to", "/")
~>	c.Redirect(http.StatusTemporaryRedirect, dest)
}
