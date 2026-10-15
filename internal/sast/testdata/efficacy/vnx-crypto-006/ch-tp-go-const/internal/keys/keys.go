package keys

import (
	"crypto/rand"
	"crypto/rsa"
)

const keyBits = 1024

func New() (*rsa.PrivateKey, error) {
~>	return rsa.GenerateKey(rand.Reader, keyBits)
}
