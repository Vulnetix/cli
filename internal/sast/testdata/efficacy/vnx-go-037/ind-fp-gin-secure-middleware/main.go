package main

import (
	"net/http"

	"github.com/gin-contrib/secure"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	r.Use(secure.New(secure.Config{FrameDeny: true, ContentTypeNosniff: true}))
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.tmpl", nil)
	})
	r.Run()
}
