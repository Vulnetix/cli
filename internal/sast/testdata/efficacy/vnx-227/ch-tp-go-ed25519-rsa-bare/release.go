package release

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
)

func Accept(pub ed25519.PublicKey, msg, sig []byte) []byte {
~>	ed25519.Verify(pub, msg, sig)
	return msg
}

func AcceptRSA(pub *rsa.PublicKey, digest, sig []byte) []byte {
~>	rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig)
	return digest
}
