package crypto

import (
	"crypto/aes"
	"testing"
)

func TestKAT(t *testing.T) {
	block, _ := aes.NewCipher(make([]byte, 16))
	src := make([]byte, 64)
	dst := make([]byte, 64)
	for i := 0; i < len(src); i += 16 {
		block.Encrypt(dst[i:i+16], src[i:i+16])
	}
}
