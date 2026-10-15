package keys

import (
	"crypto/rand"
	"crypto/rsa"
)

const keyBits = 4096

// rsa.GenerateKey(rand.Reader, 1024) was the old default.
func New() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, keyBits)
}
