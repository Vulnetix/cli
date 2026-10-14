package pin

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
)

var errPin = errors.New("certificate does not match pin")

// The default chain check is replaced by an explicit pin check, which is
// the documented way to verify a certificate the system roots do not cover.
func Pinned(want [32]byte) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			for _, c := range raw {
				if sha256.Sum256(c) == want {
					return nil
				}
			}
			return errPin
		},
	}
}

func WithRoots(pool *x509.CertPool, name string) *tls.Config {
	cfg := &tls.Config{InsecureSkipVerify: true}
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		opts := x509.VerifyOptions{Roots: pool, DNSName: name, Intermediates: x509.NewCertPool()}
		for _, c := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(c)
		}
		_, err := cs.PeerCertificates[0].Verify(opts)
		return err
	}
	return cfg
}
