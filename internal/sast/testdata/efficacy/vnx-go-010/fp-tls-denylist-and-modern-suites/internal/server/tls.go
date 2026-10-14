package server

import "crypto/tls"

// weak is rejected when an operator lists it in the config file.
var weak = map[uint16]bool{
	tls.TLS_RSA_WITH_RC4_128_SHA:            true,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:       true,
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: true,
}

func Config(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}
}

func Allowed(id uint16) bool {
	if id == tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA {
		return false
	}
	return !weak[id]
}
