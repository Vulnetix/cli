package export

import (
	"crypto/aes"
	"errors"
)

var errShort = errors.New("input not block aligned")

func obfuscate(key, src []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, len(src))
	n := len(src) / aes.BlockSize
	for i := 0; i < n; i++ {
		off := i * aes.BlockSize
		end := off + aes.BlockSize
		if end > len(src) {
			return nil, errShort
		}
		// one record id per block, encrypted in place
		in := src[off:end]
		out := dst[off:end]
~>		blk.Encrypt(out[:], in[:])
	}
	return dst, nil
}
