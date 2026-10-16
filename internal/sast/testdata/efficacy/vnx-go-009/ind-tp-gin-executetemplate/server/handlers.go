package server

import (
	"text/template"

	"github.com/gin-gonic/gin"
)

var tpls = template.Must(template.New("root").Parse(`{{define "profile"}}<div class="bio">{{.Bio}}</div>{{end}}`))

func Profile(c *gin.Context) {
	bio := c.PostForm("bio")
~>	tpls.ExecuteTemplate(c.Writer, "profile", map[string]string{"Bio": bio})
}
