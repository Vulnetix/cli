package crypt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

func Sign(k *rsa.PrivateKey, digest []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest)
}

func Seal(pub *rsa.PublicKey, m []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, m, nil)
}
