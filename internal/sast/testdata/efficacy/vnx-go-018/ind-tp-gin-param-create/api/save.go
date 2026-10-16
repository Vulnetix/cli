package api

import (
	"os"

	"github.com/gin-gonic/gin"
)

func Save(c *gin.Context) {
	name := c.Param("name")
~>	f, err := os.Create("/data/" + name)
	if err != nil {
		c.Status(500)
		return
	}
	defer f.Close()
	c.Status(201)
}
