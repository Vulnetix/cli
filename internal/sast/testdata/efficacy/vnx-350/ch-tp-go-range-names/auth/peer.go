package auth

import (
	"net"
	"net/http"
	"strings"
)

func trustedPeer(r *http.Request) bool {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
~>	names, err := net.LookupAddr(ip)
	if err != nil {
		return false
	}
	for _, n := range names {
		if strings.HasSuffix(strings.TrimSuffix(n, "."), ".example.com") {
			return true
		}
	}
	return false
}
