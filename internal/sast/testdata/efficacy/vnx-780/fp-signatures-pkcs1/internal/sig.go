package internal

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

func Sign(priv *rsa.PrivateKey, digest []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest)
}

func Verify(pub *rsa.PublicKey, digest, sig []byte) error {
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig)
}
