package tests

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

func TestCBCVector(t *testing.T) {
	block, _ := aes.NewCipher(make([]byte, 16))
	iv := []byte("0000000000000000")
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(make([]byte, 16), make([]byte, 16))
}
