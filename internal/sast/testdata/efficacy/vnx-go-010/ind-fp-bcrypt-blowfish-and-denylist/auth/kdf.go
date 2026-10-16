package auth

import (
	"crypto/tls"

	"golang.org/x/crypto/blowfish"
)

func keySchedule(salt, key []byte) (*blowfish.Cipher, error) {
	return blowfish.NewSaltedCipher(key, salt)
}

func banned(id uint16) bool {
	return id == tls.TLS_RSA_WITH_RC4_128_SHA || id == tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA
}

// Never call des.NewCipher or rc4.NewCipher here; the string "3des-cbc" is rejected.
var note = "do not enable arcfour or des.NewTripleDESCipher"
