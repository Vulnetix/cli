package client

import (
	"crypto/tls"
	"crypto/x509"
)

type Options struct {
	Insecure bool
}

// InsecureSkipVerify: true must never be used here.
const doc = "InsecureSkipVerify: true disables verification"

func Config(opts Options, pool *x509.CertPool) *tls.Config {
	cfg := &tls.Config{
		RootCAs:            pool,
		InsecureSkipVerify: opts.Insecure,
	}
	if cfg.InsecureSkipVerify == true {
		log("insecure mode")
	}
	return cfg
}

func Pinned(verify func([][]byte, [][]*x509.Certificate) error) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: verify,
	}
}

func Strict() *tls.Config {
	return &tls.Config{InsecureSkipVerify: false, MinVersion: tls.VersionTLS13}
}

func log(string) {}
