package client

import (
	"crypto/tls"
	"crypto/x509"
)

func Cfg(pin func([][]byte, [][]*x509.Certificate) error) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: pin,
	}
}
