package digests

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
)

func Sum(data []byte) [32]byte { return sha256.Sum256(data) }

func Sum512(data []byte) [64]byte { return sha512.Sum512(data) }

var template = x509.Certificate{SignatureAlgorithm: x509.SHA256WithRSA}
