package enc

import "crypto/aes"

func Seal(key, src []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	bs := block.BlockSize()
	dst := make([]byte, len(src))
	for i := 0; i < len(src); i += bs {
~>		block.Encrypt(dst[i:i+bs], src[i:i+bs])
	}
	return dst
}

func Open(key, src []byte) []byte {
	c, _ := aes.NewCipher(key)
	dst := make([]byte, len(src))
	out := dst
	for len(src) > 0 {
~>		c.Decrypt(dst, src[:aes.BlockSize])
		src = src[aes.BlockSize:]
		dst = dst[aes.BlockSize:]
	}
	return out
}
