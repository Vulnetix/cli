package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"math/rand"
)

func Seal(key, plain []byte) []byte {
	block, _ := aes.NewCipher(key)
	iv := make([]byte, aes.BlockSize)
~>	rand.Read(iv)
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	return append(iv, out...)
}
