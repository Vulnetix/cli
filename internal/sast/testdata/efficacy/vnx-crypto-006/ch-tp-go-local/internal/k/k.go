package k

import (
	"crypto/rand"
	"crypto/rsa"
)

func Gen() *rsa.PrivateKey {
	bits := 1024
~>	key, _ := rsa.GenerateKey(rand.Reader, bits)
	return key
}
