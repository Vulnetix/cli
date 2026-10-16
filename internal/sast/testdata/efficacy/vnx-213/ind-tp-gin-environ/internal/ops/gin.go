package ops

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func Register(r *gin.Engine) {
	r.GET("/debug/env", func(c *gin.Context) {
~>		c.JSON(http.StatusOK, gin.H{"env": os.Environ()})
	})
}
