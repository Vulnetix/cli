package auth

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"

	"golang.org/x/crypto/bcrypt"
)

func Login(u *User, password string) *Session {
~>	bcrypt.CompareHashAndPassword(u.Hash, []byte(password))
	return newSession(u)
}

func CheckWebhook(mac, expected []byte, body []byte) {
~>	hmac.Equal(mac, expected)
	process(body)
}

func VerifyRelease(pub *rsa.PublicKey, digest, sig []byte) {
~>	_ = rsa.VerifyPKCS1v15(pub, 0, digest, sig)
~>	ed25519.Verify(
		edKey,
		digest,
		sig,
	)
	install(digest)
}
