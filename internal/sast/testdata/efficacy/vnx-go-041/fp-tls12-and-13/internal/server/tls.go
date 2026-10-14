package server

import "crypto/tls"

func modern() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}
}

func strict(cfg *tls.Config) {
	cfg.MinVersion = tls.VersionTLS13
	minVer := uint16(tls.VersionTLS12)
	cfg.MinVersion = minVer
}

var hexConf = &tls.Config{MinVersion: 0x0303}
