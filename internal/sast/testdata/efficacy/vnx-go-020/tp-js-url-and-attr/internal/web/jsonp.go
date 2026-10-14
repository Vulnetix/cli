package web

import (
	"html/template"
	"net/http"

	"github.com/gin-gonic/gin"
)

func JSONP(w http.ResponseWriter, r *http.Request) {
	cb := r.URL.Query().Get("callback")
	next := r.FormValue("next")
	data := struct {
		Callback template.JS
		Next     template.URL
	}{
~>		Callback: template.JS(cb),
~>		Next:     template.URL(next),
	}
	_ = data
}

func Banner(c *gin.Context) {
	style := c.Query("style")
	c.HTML(http.StatusOK, "banner.tmpl", gin.H{
~>		"Style": template.CSS(style),
~>		"Attr":  template.HTMLAttr(c.PostForm("attr")),
	})
}
