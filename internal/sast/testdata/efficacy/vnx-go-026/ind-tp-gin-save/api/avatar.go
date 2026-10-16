package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func Avatar(c *gin.Context) {
	f, err := c.FormFile("avatar")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
~>	if err := c.SaveUploadedFile(f, "static/avatars/"+f.Filename); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusCreated)
}
