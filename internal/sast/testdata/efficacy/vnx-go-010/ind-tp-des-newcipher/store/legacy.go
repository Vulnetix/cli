package store

import (
	"crypto/cipher"
	"crypto/des"
)

func legacyBlock(key []byte) (cipher.Block, error) {
~>	return des.NewCipher(key)
}
