package server

import (
	"net"
	"net/http"
	"strings"
)

func peer(r *http.Request) string {
~>	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		if i := strings.IndexByte(xf, ','); i > 0 {
			return strings.TrimSpace(xf[:i])
		}
		return strings.TrimSpace(xf)
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func strip(r *http.Request) {
	r.Header.Del("X-Forwarded-For")
	r.Header.Set("X-Real-IP", r.RemoteAddr)
}
