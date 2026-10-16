package enc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

func Seal(pub *rsa.PublicKey, msg []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, msg, nil)
}

func Sign(k *rsa.PrivateKey, h []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h)
}
