package box

import (
	"crypto/cipher"
	"crypto/rand"
)

var nonce = make([]byte, 12)

func init() {
	rand.Read(nonce)
}

func Seal(aead cipher.AEAD, msg []byte) []byte {
~>	return aead.Seal(nil, nonce, msg, nil)
}
