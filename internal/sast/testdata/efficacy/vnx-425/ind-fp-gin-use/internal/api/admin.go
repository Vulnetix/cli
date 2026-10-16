package api

import "github.com/gin-gonic/gin"

func AdminRoutes(r *gin.Engine) {
	g := r.Group("/admin")
	g.Use(AuthRequired(), RequireRole("admin"))
	g.GET("/stats", stats)
}

func stats(c *gin.Context) {
	c.JSON(200, collect())
}
