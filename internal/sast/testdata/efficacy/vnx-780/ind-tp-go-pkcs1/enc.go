package enc

import (
	"crypto/rand"
	"crypto/rsa"
)

func Seal(pub *rsa.PublicKey, msg []byte) ([]byte, error) {
~>	return rsa.EncryptPKCS1v15(rand.Reader, pub, msg)
}
