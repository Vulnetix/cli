package server

import (
	"net/http"

	"golang.org/x/time/rate"
)

var limiter = rate.NewLimiter(1, 5)

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if !limiter.Allow() {
		http.Error(w, "slow down", http.StatusTooManyRequests)
		return
	}
	w.WriteHeader(200)
}
