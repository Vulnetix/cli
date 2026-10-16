package net

import "net"

// Example: redis.NewClient(&redis.Options{Addr: "10.1.1.1:6379"})
func outbound() (net.Conn, error) {
	return net.Dial("udp", "8.8.8.8:80")
}

func log() string {
	return "see mysql://10.0.0.5/db for the schema"
}
