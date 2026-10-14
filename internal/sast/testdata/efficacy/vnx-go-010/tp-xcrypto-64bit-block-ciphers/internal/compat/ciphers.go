package compat

import (
	"crypto/cipher"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/xtea"
)

func newBlock(alg string, key []byte) (cipher.Block, error) {
	switch alg {
	case "blowfish":
~>		return blowfish.NewCipher(key)
	case "cast5":
~>		return cast5.NewCipher(key)
	default:
~>		return xtea.NewCipher(key)
	}
}
