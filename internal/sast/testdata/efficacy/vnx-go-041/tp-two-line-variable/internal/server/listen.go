package server

import (
	"crypto/tls"
	"net"
)

func listen(addr string, certs []tls.Certificate) (net.Listener, error) {
	minVer := uint16(tls.VersionTLS10)
	conf := &tls.Config{
		Certificates: certs,
~>		MinVersion:   minVer,
	}
	return tls.Listen("tcp", addr, conf)
}

func listenOld(addr string) (net.Listener, error) {
	var oldest uint16 = tls.VersionTLS11
	conf := &tls.Config{}
~>	conf.MinVersion = oldest
	return tls.Listen("tcp", addr, conf)
}
