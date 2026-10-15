package crypto

import (
	"crypto/aes"
	"encoding/hex"
	"os"
)

func block() error {
	aesKey, err := hex.DecodeString(os.Getenv("AES_KEY_HEX"))
	if err != nil {
		return err
	}
	_, err = aes.NewCipher(aesKey)
	return err
}
