package web

import (
	"html/template"

	"github.com/gin-gonic/gin"
)

func Page(c *gin.Context) {
	cb := c.Query("callback")
~>	c.HTML(200, "page.tmpl", gin.H{"Init": template.JS(cb)})
}
