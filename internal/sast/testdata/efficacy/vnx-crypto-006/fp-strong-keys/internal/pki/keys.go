package pki

import (
	"crypto/rand"
	"crypto/rsa"
)

func Strong(bits int) (*rsa.PrivateKey, error) {
	if bits < 2048 {
		bits = 4096
	}
	return rsa.GenerateKey(rand.Reader, bits)
}

func Default() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}
