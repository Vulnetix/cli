package pki

import (
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

func legacyTemplate(cn string, serial *big.Int) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:       serial,
		Subject:            pkix.Name{CommonName: cn},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(5, 0, 0),
~>		SignatureAlgorithm: x509.SHA1WithRSA,
	}
}

func subjectKeyID(pub []byte) []byte {
~>	sum := sha1.Sum(pub)
	return sum[:]
}
