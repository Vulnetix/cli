package vault

import (
	"crypto/cipher"
	legacydes "crypto/des"
)

func wrapKey(kek []byte) (cipher.Block, error) {
~>	return legacydes.NewTripleDESCipher(kek)
}
