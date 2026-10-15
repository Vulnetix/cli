package tlsutil

import (
	"crypto/tls"
	"log"
)

func Harden(cfg *tls.Config) {
	if cfg.MinVersion < tls.VersionTLS12 {
		log.Printf("raising MinVersion from %x (below %x)", cfg.MinVersion, tls.VersionTLS11)
		cfg.MinVersion = tls.VersionTLS12
	}
	if cfg.MaxVersion != 0 && cfg.MaxVersion <= tls.VersionTLS11 {
		cfg.MaxVersion = 0
	}
}

func Name(v uint16) string {
	switch v {
	case tls.VersionTLS10, tls.VersionTLS11:
		return "deprecated"
	}
	return tls.VersionName(v)
}

var rejected = []uint16{tls.VersionSSL30, tls.VersionTLS10, tls.VersionTLS11}
