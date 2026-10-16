package svc

import (
	"net"
	"os"
)

func dial() (net.Conn, error) {
	addr := os.Getenv("CACHE_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}
	_, _ = net.Dial("tcp", "127.0.0.1:9090")
	return net.Dial("tcp", addr)
}

var version = "go1.22.3.1"
var trusted = []string{"10.0.0.0/8"}
