package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()
~>	r.POST("/api/login", func(c *gin.Context) {
		checkPassword(c)
	})
	r.GET("/health", func(c *gin.Context) { c.Status(200) })
	r.POST("/login", loginHandler)
	r.Run()
}
