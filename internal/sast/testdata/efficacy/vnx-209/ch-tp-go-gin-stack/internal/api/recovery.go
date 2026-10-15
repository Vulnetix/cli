package api

import (
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"
)

func Recovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				trace := string(debug.Stack())
~>				c.JSON(http.StatusInternalServerError, gin.H{"panic": r, "trace": trace})
			}
		}()
		c.Next()
	}
}
