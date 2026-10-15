package web

import (
	"html/template"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Banner(c *gin.Context) {
	c.HTML(http.StatusOK, "banner.tmpl", gin.H{
~>		"content": template.HTML(c.Query("banner")),
	})
}

var page = template.Must(template.New("p").Parse(`<div>{{.Msg}}</div>`))

func Notice(w http.ResponseWriter, r *http.Request) {
	page.Execute(w, map[string]any{
~>		"Msg": template.HTML(r.URL.Query().Get("notice")),
	})
}
