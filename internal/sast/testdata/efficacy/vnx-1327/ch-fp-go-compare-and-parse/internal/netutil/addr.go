package netutil

import "net"

var unspecified = net.ParseIP("0.0.0.0")

func IsWildcard(host string) bool {
	return host == "0.0.0.0" || host == "::" || net.ParseIP(host).Equal(unspecified)
}
