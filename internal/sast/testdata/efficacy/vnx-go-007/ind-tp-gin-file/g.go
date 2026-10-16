package web

import "github.com/gin-gonic/gin"

func Get(c *gin.Context) {
	fn := c.Query("f")
~>	c.File("/var/uploads/" + fn)
}
