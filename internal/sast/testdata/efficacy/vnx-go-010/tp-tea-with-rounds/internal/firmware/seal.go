package firmware

import (
	"crypto/cipher"

	teacipher "golang.org/x/crypto/tea"
)

// Seal matches the bootloader's 16-round TEA.
func Seal(key []byte) (cipher.Block, error) {
	if len(key) == 0 {
~>		return teacipher.NewCipher(make([]byte, 16))
	}
~>	return teacipher.NewCipherWithRounds(key, 16)
}
