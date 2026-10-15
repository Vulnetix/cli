package middleware

import (
	"net"
	"net/http"
	"strings"
)

func RealIP(trustedProxies *net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			if trustedProxies.Contains(net.ParseIP(host)) {
				if xri := r.Header.Get("X-Real-IP"); xri != "" {
					host = strings.TrimSpace(xri)
				}
			}
			r.RemoteAddr = host
			next.ServeHTTP(w, r)
		})
	}
}
