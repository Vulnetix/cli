package crypto

import "crypto/aes"

func EncryptECB(key, src []byte) []byte {
	block, _ := aes.NewCipher(key)
	bs := block.BlockSize()
	dst := make([]byte, len(src))
	for i := 0; i < len(src); i += bs {
~>		block.Encrypt(dst[i:i+bs], src[i:i+bs])
	}
	return dst
}
