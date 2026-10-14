package listener

import (
	"crypto/tls"
	"net"
)

func Listen(addr string, cert tls.Certificate) (net.Listener, error) {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
~>			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
~>			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		},
	}
	return tls.Listen("tcp", addr, cfg)
}
