package server

import "crypto/tls"

// LegacyConfig keeps old embedded clients connecting.
func LegacyConfig(cert tls.Certificate) *tls.Config {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
~>			tls.TLS_RSA_WITH_RC4_128_SHA,
~>			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
	}
~>	cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA)
	return cfg
}
