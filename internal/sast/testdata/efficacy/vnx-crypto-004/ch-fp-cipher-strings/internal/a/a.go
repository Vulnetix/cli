package a

import (
	"crypto/aes"
	"crypto/cipher"
)

func Seal(k []byte) cipher.AEAD {
	b, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(b)
	return g
}
