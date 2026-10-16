package api

import (
	"path/filepath"

	"github.com/gin-gonic/gin"
)

func Download(c *gin.Context) {
~>	c.File(filepath.Join("uploads", c.Param("file")))
}
