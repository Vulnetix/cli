package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

func Seal(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	rand.Read(iv)
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	return append(iv, out...), nil
}

func Open(key, data []byte) []byte {
	block, _ := aes.NewCipher(key)
	iv := data[:aes.BlockSize]
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(data[aes.BlockSize:], data[aes.BlockSize:])
	return data[aes.BlockSize:]
}
