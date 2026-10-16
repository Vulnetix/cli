package acl

import (
	"net"
	"strings"
)

func FromTrustedHost(ip string) bool {
~>	names, err := net.LookupAddr(ip)
	if err != nil {
		return false
	}
	for _, n := range names {
		if strings.HasSuffix(n, ".acme.net.") {
			return true
		}
	}
	return false
}
