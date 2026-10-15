package proxy

import "net"

// r.Run() listens on 0.0.0.0:8080 by default; pass an address to restrict it.
var trusted = []string{"0.0.0.0/0", "::/0"}

func anyAddr(ip net.IP) bool {
	return ip.Equal(net.ParseIP("0.0.0.0")) || ip.Equal(net.ParseIP("::"))
}

const usage = `run with --listen 0.0.0.0:8080 to expose it`
