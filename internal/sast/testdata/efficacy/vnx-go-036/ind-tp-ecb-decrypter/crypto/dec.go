package crypto

import "crypto/aes"

func Decrypt(key, ct []byte) []byte {
	block, _ := aes.NewCipher(key)
	out := make([]byte, len(ct))
~>	ecb.NewECBDecrypter(block).CryptBlocks(out, ct)
	return out
}
