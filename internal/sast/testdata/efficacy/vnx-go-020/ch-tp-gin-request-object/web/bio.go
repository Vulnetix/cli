package web

import (
	"html/template"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Bio(c *gin.Context) {
	c.HTML(http.StatusOK, "bio.tmpl", gin.H{
~>		"bio": template.HTML(c.Request.FormValue("bio")),
	})
}
