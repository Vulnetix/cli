package netutil

import (
	"crypto/tls"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// OutboundIP returns the address of the interface used for outbound traffic.
// No packet is sent: UDP dial only selects a route.
func OutboundIP() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP, nil
}

func PubSub() (*grpc.ClientConn, error) {
	creds := credentials.NewTLS(&tls.Config{})
	return grpc.Dial("pubsub.googleapis.com:443", grpc.WithTransportCredentials(creds))
}
