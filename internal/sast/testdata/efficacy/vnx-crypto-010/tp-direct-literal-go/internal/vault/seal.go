package vault

import (
	"crypto/aes"
	"crypto/cipher"
)

func encryptCBC(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(plaintext))
~>	mode := cipher.NewCBCEncrypter(block, []byte("1234567890123456"))
	mode.CryptBlocks(out, plaintext)
	return out, nil
}

func encryptCTR(key, plaintext []byte) []byte {
	block, _ := aes.NewCipher(key)
	out := make([]byte, len(plaintext))
~>	stream := cipher.NewCTR(block, make([]byte, aes.BlockSize))
	stream.XORKeyStream(out, plaintext)
	return out
}

func seal(gcm cipher.AEAD, plaintext []byte) []byte {
~>	return gcm.Seal(nil, []byte("unique-nonce"), plaintext, nil)
}
