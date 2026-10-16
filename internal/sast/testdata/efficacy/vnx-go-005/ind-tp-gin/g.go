package web

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func Out(c *gin.Context) {
	target := c.Query("url")
~>	c.Redirect(http.StatusFound, target)
}
