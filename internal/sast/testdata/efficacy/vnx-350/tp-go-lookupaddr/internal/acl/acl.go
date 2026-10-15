package acl

import (
	"net"
	"strings"
)

func Trusted(ip string) bool {
~>	names, err := net.LookupAddr(ip)
	if err != nil {
		return false
	}
	for _, n := range names {
		if strings.HasSuffix(n, ".example.com.") {
			return true
		}
	}
	return false
}
