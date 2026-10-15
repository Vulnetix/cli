package license

import (
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"errors"
)

func Load(pub ed25519.PublicKey, body, sig []byte) ([]byte, error) {
	if !ed25519.Verify(pub, body, sig) {
		return nil, errors.New("bad signature")
	}
	ok :=
		ed25519.Verify(pub, body, sig)
	_ = ok
	if err := rsa.VerifyPSS(nil, crypto.SHA256, body, sig, nil); err != nil {
		return nil, err
	}
	err := rsa.VerifyPKCS1v15(nil, crypto.SHA256, body, sig)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func Equal(a, b []byte) bool {
	return hmac.Equal(a, b)
}
