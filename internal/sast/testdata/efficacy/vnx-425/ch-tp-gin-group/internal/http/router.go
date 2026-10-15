package http

import "github.com/gin-gonic/gin"

func NewRouter(h *Handlers) *gin.Engine {
	r := gin.New()
	r.GET("/healthz", h.Health)
~>	admin := r.Group("/admin")
	{
		admin.POST("/users/:id/ban", h.BanUser)
		admin.DELETE("/cache", h.FlushCache)
	}
	return r
}
