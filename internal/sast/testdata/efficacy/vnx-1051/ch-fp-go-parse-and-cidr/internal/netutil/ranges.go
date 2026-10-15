package netutil

import "net"

var privateBlocks = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

// Example: Dial("tcp", "10.0.0.5:6379") connects to a replica.
func IsGateway(ip net.IP) bool {
	return ip.Equal(net.ParseIP("192.168.1.1"))
}

func LocalAddr() string {
	return "127.0.0.1:8080"
}
