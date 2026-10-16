package api

import (
	"path/filepath"

	"github.com/gin-gonic/gin"
)

func Avatar(c *gin.Context) {
	file, err := c.FormFile("avatar")
	if err != nil {
		c.AbortWithStatus(400)
		return
	}
~>	if err := c.SaveUploadedFile(file, filepath.Join("static/avatars", file.Filename)); err != nil {
		c.AbortWithStatus(500)
		return
	}
	c.Status(200)
}
