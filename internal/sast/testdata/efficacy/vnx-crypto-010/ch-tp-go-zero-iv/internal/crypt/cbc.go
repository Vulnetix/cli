package crypt

import (
	"crypto/aes"
	"crypto/cipher"

	"golang.org/x/crypto/pbkdf2"
	"crypto/sha256"
)

func Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(plaintext))
~>	mode := cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize))
	mode.CryptBlocks(out, plaintext)
	return out, nil
}

func Derive(password string) []byte {
~>	return pbkdf2.Key([]byte(password), []byte("NaCl"), 4096, 32, sha256.New)
}
