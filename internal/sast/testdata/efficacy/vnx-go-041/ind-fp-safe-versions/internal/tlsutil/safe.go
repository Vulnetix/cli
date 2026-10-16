package tlsutil

import "crypto/tls"

func Server(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
}

func Internal() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
}
