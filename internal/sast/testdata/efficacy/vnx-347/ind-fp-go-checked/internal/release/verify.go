package release

import (
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"errors"
)

func Check(pub ed25519.PublicKey, blob, sig []byte) error {
	if !ed25519.Verify(pub, blob, sig) {
		return errors.New("bad signature")
	}
	return nil
}

func CheckRSA(pub *rsa.PublicKey, digest, sig []byte) error {
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig)
}

func MacOK(a, b []byte) bool {
	ok := hmac.Equal(a, b)
	return ok
}
