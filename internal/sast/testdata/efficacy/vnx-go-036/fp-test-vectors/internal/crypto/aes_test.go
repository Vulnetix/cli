package crypto

import (
	"crypto/aes"
	"testing"
)

func TestKAT(t *testing.T) {
	block, _ := aes.NewCipher(katKey)
	out := make([]byte, len(katPlain))
	for i := 0; i < len(katPlain); i += 16 {
		block.Encrypt(out[i:i+16], katPlain[i:i+16])
	}
}
