package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
~>		c.HTML(http.StatusOK, "index.tmpl", gin.H{"title": "Home"})
	})
	r.Run(":8080")
}
