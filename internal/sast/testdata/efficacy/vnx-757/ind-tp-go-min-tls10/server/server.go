package server

import (
	"crypto/tls"
	"net/http"
)

func newServer(h http.Handler) *http.Server {
	cfg := &tls.Config{
~>		MinVersion: tls.VersionTLS10,
	}
	return &http.Server{Addr: ":8443", Handler: h, TLSConfig: cfg}
}
