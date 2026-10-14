package server

import (
	"crypto/tls"
	"net/http"
)

// Older POS terminals still need these.
var legacySuites = []uint16{
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
~>	tls.TLS_RSA_WITH_RC4_128_SHA,
~>	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
}

func NewServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:    addr,
		Handler: h,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS10,
			CipherSuites: legacySuites,
		},
	}
}
