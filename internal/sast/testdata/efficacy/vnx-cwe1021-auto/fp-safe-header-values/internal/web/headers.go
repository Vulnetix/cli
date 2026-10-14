package web

import (
	"net/http"

	"github.com/labstack/echo/v4/middleware"
)

func Secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'self'")
		next.ServeHTTP(w, r)
	})
}

var EchoSecure = middleware.SecureWithConfig(middleware.SecureConfig{
	XFrameOptions: "SAMEORIGIN",
})
