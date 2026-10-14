package router

import (
	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func Admin(r *gin.Engine) {
~>	admin := r.Group("/admin", gin.BasicAuth(gin.Accounts{"admin": "admin"}))
	admin.GET("/stats", stats)
}

func Metrics(r chi.Router) {
~>	r.Use(middleware.BasicAuth("metrics", map[string]string{"prometheus": "secret"}))
}

// Credentials loaded at startup are not hard-coded.
func Ops(r *gin.Engine, user, pass string) {
	r.Group("/ops", gin.BasicAuth(gin.Accounts{user: pass}))
}

func stats(*gin.Context) {}
