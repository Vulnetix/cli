package httpx

import (
	"net"
	"net/http"
)

func ClientIP(r *http.Request) string {
~>	ip := r.Header.Get("X-Real-IP")
	if ip == "" {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		ip = host
	}
	return ip
}
