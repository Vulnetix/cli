package modern

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"

	"golang.org/x/crypto/chacha20poly1305"
)

func AEAD(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}

func AES(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}

// des is imported only for its block size, used when parsing old blobs.
const legacyBlock = des.BlockSize
