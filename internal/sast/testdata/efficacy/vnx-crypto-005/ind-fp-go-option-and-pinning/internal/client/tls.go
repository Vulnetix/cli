package client

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
)

type Options struct {
	Insecure bool
	Pin      [32]byte
}

func configFor(opts Options) *tls.Config {
	return &tls.Config{InsecureSkipVerify: opts.Insecure}
}

func pinned(opts Options) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 || sha256.Sum256(raw[0]) != opts.Pin {
				return errors.New("certificate pin mismatch")
			}
			return nil
		},
	}
}

func fromFlag(insecure bool) *tls.Config {
	cfg := &tls.Config{}
	if insecure {
		cfg.InsecureSkipVerify = true
	}
	return cfg
}
