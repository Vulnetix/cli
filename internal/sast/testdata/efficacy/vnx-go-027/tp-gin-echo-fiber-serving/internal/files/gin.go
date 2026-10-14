package files

import (
	"path/filepath"

	"github.com/gin-gonic/gin"
)

func Download(c *gin.Context) {
~>	c.File(filepath.Join("./downloads", c.Param("file")))
}

func Report(c *gin.Context) {
	name := c.Query("report")
~>	c.FileAttachment("./reports/"+name, name)
}
