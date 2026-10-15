package config

import (
	"crypto/tls"
	"fmt"
)

var tlsVersions = map[string]uint16{
	"1.0": tls.VersionTLS10,
	"1.1": tls.VersionTLS11,
	"1.2": tls.VersionTLS12,
	"1.3": tls.VersionTLS13,
}

func Build(minName string) (*tls.Config, error) {
	v, ok := tlsVersions[minName]
	if !ok || v < tls.VersionTLS12 {
		return nil, fmt.Errorf("unsupported minimum TLS version %q", minName)
	}
	cfg := &tls.Config{}
	cfg.MinVersion = tlsVersions[minName]
	return cfg, nil
}
