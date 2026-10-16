package httpx

import (
	"log"
	"net"
	"net/http"
)

func PeerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	log.Printf("peer=%s xff=%q", host, r.Header.Get("X-Forwarded-For"))
	return host
}
