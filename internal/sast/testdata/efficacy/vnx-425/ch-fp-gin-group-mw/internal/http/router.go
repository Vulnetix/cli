package http

import "github.com/gin-gonic/gin"

func NewRouter(h *Handlers, accounts gin.Accounts) *gin.Engine {
	r := gin.New()
	admin := r.Group("/admin", gin.BasicAuth(accounts))
	{
		admin.POST("/users/:id/ban", h.BanUser)
	}
	staff := r.Group("/staff", RequireRole("staff"))
	staff.GET("/reports", h.Reports)
	public := r.Group("/api")
	public.GET("/items", h.Items)
	return r
}
