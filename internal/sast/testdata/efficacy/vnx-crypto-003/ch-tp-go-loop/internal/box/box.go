package box

import "crypto/aes"

func Seal(key, src []byte) []byte {
	block, _ := aes.NewCipher(key)
	dst := make([]byte, len(src))
	bs := block.BlockSize()
	for i := 0; i < len(src); i += bs {
~>		block.Encrypt(dst[i:i+bs], src[i:i+bs])
	}
	return dst
}
