package web

import "github.com/gin-gonic/gin"

func Download(c *gin.Context) {
	name := c.Query("file")
~>	c.Header("Content-Disposition", "attachment; filename="+name)
	c.File("/srv/exports/report.csv")
}
