package web

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func AfterLogin(c *gin.Context) {
	if !authenticate(c) {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
~>	c.Redirect(http.StatusFound, c.Query("return_to"))
}
