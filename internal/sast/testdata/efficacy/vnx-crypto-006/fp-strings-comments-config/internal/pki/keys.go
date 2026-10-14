package pki

import (
	"crypto/rand"
	"crypto/rsa"
)

// rsa.GenerateKey(rand.Reader, 1024) was the old default.
const msg = "rsa.GenerateKey(rand.Reader, 1024) is not allowed"

func FromConfig(cfg Config) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, cfg.Bits)
}

type Config struct{ Bits int }
