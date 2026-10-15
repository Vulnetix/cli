package seal

import (
	"crypto/cipher"
	"crypto/rand"
)

var nonce = make([]byte, 12)

func init() {
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
}

func Seal(aead cipher.AEAD, plaintext []byte) []byte {
~>	return aead.Seal(nil, nonce, plaintext, nil)
}
