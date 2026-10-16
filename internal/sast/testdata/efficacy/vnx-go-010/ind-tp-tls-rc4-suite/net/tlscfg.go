package net

import "crypto/tls"

func LegacyConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS10,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
~>			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		},
	}
}
