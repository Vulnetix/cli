package acl

import (
	"net"
	"strings"
)

func Verified(ip string) bool {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return false
	}
	addrs, err := net.LookupHost(names[0])
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if a == ip && strings.HasSuffix(names[0], ".acme.net.") {
			return true
		}
	}
	return false
}
