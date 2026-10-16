package crypto

import (
	"crypto/aes"

	"github.com/example/ecb"
)

func Encrypt(key, pt []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(pt))
~>	mode := ecb.NewECBEncrypter(block)
	mode.CryptBlocks(out, pt)
	return out, nil
}
