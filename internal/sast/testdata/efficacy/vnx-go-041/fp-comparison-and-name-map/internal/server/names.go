package server

import (
	"crypto/tls"
	"log"
)

var versionNames = map[uint16]string{
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2",
}

func audit(state tls.ConnectionState, cfg *tls.Config) {
	if state.Version == tls.VersionTLS10 || state.Version == tls.VersionTLS11 {
		log.Println("peer negotiated a deprecated version")
	}
	if cfg.MinVersion <= tls.VersionTLS11 {
		cfg.MinVersion = tls.VersionTLS12
	}
	switch state.Version {
	case tls.VersionTLS10:
		log.Println("tls1.0")
	}
}
