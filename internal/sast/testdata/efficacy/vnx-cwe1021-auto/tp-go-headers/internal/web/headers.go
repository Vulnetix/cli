package web

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/labstack/echo/v4/middleware"
)

func Embeddable(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
~>		w.Header().Set("X-Frame-Options", "ALLOWALL")
		next.ServeHTTP(w, r)
	})
}

func StripFrame(w http.ResponseWriter) {
~>	w.Header().Del("X-Frame-Options")
}

func GinCSP(c *gin.Context) {
~>	c.Header("Content-Security-Policy", "default-src 'self'; frame-ancestors *")
	c.Next()
}

var EchoSecure = middleware.SecureWithConfig(middleware.SecureConfig{
	XSSProtection:      "1; mode=block",
	ContentTypeNosniff: "nosniff",
~>	XFrameOptions:      "",
})
