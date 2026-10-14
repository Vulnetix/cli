package pki

import (
	"crypto/rand"
	"crypto/rsa"
)

const legacyBits = 1024

func Weak() (*rsa.PrivateKey, error) {
~>	return rsa.GenerateKey(rand.Reader, 1024)
}

func FromConst() (*rsa.PrivateKey, error) {
~>	return rsa.GenerateKey(rand.Reader, legacyBits)
}

func MultiPrime() (*rsa.PrivateKey, error) {
~>	return rsa.GenerateMultiPrimeKey(rand.Reader, 3, 768)
}
