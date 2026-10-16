package legacy

import (
	"crypto/aes"
	"errors"
)

// EncryptBlocks encrypts data that the old device firmware expects block by block.
func EncryptBlocks(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(plaintext)%bs != 0 {
		return nil, errors.New("plaintext is not a multiple of the block size")
	}
	out := make([]byte, len(plaintext))
	for start := 0; start < len(plaintext); start += bs {
~>		block.Encrypt(out[start:start+bs], plaintext[start:start+bs])
	}
	return out, nil
}
