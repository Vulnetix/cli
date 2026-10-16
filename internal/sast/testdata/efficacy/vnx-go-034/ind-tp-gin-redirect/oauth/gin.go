package oauth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func callback(c *gin.Context) {
	code := "abc"
~>	c.Redirect(http.StatusFound, c.Query("redirect_uri")+"?code="+code)
}
