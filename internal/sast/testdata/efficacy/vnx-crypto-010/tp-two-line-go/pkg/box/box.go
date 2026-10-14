package box

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/pbkdf2"
)

func Seal(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
~>	var nonce [12]byte
	return gcm.Seal(nil, nonce[:], plaintext, nil), nil
}

func Decrypt(key, ct []byte) []byte {
	block, _ := aes.NewCipher(key)
~>	iv := []byte("fedcba9876543210")
	mode := cipher.NewCBCDecrypter(block, iv)
	out := make([]byte, len(ct))
	mode.CryptBlocks(out, ct)
	return out
}

func DeriveKey(password string) []byte {
~>	return pbkdf2.Key([]byte(password), []byte("box-salt"), 4096, 32, sha256.New)
}

func Box(msg []byte, key *[32]byte) []byte {
~>	var nonce [24]byte
	return secretbox.Seal(nil, msg, &nonce, key)
}

func Stream(block cipher.Block, data []byte) []byte {
~>	var iv [16]byte // zero
	out := make([]byte, len(data))
	cipher.NewCTR(block, iv[:]).XORKeyStream(out, data)
	return out
}
