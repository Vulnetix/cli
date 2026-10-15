package httpx

import (
	"net"
	"net/http"
	"strings"
)

func ClientIP(r *http.Request) string {
~>	ip := r.Header.Get("X-Real-IP")
	if ip == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	return strings.TrimSpace(ip)
}
