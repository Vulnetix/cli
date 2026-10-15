package license

import (
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
)

func Load(pub ed25519.PublicKey, body, sig []byte) []byte {
~>	ed25519.Verify(pub, body, sig)
	return body
}

func LoadRSA(pub *rsa.PublicKey, digest, sig []byte) []byte {
~>	_ = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig)
	return digest
}

func Webhook(mac, expected []byte) {
~>	hmac.Equal(mac, expected)
	process()
}
