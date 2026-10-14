package server

import "crypto/tls"

func newTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
~>		MinVersion:   tls.VersionTLS10,
	}
}

func legacyClient() *tls.Config {
~>	return &tls.Config{InsecureSkipVerify: false, MinVersion: tls.VersionTLS11}
}
