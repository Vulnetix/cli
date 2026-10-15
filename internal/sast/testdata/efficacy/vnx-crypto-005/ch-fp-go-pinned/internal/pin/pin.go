package pin

import (
	"crypto/tls"
	"crypto/x509"
)

func Config(insecure bool) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: insecure,
	}
}

func Strict() *tls.Config {
	return &tls.Config{InsecureSkipVerify: false, MinVersion: tls.VersionTLS13}
}

var _ = x509.NewCertPool
