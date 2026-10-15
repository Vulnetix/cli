package listener

import (
	"crypto/tls"
	"net"
)

func Listen(addr string, cert tls.Certificate, fips bool) (net.Listener, error) {
	minVer := uint16(tls.VersionTLS10)
	minVer = tls.VersionTLS12
	if fips {
		minVer = tls.VersionTLS13
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVer,
	}
	return tls.Listen("tcp", addr, cfg)
}
