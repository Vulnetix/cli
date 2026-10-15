package api

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func SetLogLevel(c *gin.Context) {
	level := c.Query("level")
~>	if err := os.Setenv("LOG_LEVEL", level); err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	c.Status(http.StatusNoContent)
}
