package transport

import (
	"crypto/tls"
	"net/http"
)

func legacyClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
~>				tls.TLS_RSA_WITH_RC4_128_SHA,
			},
		},
	}
	return &http.Client{Transport: tr}
}
