package server

import (
	"net/http"

	"github.com/go-chi/httprate"
)

func Limit(next http.Handler) http.Handler {
	return httprate.LimitByIP(10, 60)(next)
}
