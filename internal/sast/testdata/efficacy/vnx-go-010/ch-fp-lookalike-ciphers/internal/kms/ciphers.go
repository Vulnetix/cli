package kms

import (
	"crypto/aes"
	"crypto/cipher"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/twofish"

	"example.com/gm/sm4"
	"example.com/internal/hsm"
)

const rc4KeyLen = 16

type desc struct{ name string }

func New(alg string, key []byte) (cipher.Block, error) {
	switch alg {
	case "sm4":
		return sm4.NewCipher(key)
	case "twofish":
		return twofish.NewCipher(key)
	case "hsm":
		return hsm.NewCipher(key)
	}
	return aes.NewCipher(key)
}

func Stream(key, nonce []byte) (*chacha20.Cipher, error) {
	return chacha20.NewUnauthenticatedCipher(key, nonce)
}

func describe() desc {
	rc4Disabled := true
	_ = rc4Disabled
	return desc{name: "des-disabled"}
}
