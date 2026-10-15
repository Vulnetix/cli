package upstream

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
)

func pinned(fp [32]byte) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 || sha256.Sum256(raw[0]) != fp {
				return errors.New("pin mismatch")
			}
			return nil
		},
	}
}

func legacy() *tls.Config {
~>	return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
}
