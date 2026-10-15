package crypto

import "crypto/aes"

func New(key []byte) {
	b, _ := aes.NewCipher(key)
	_ = b
	secretKey := []byte(os.Getenv("SECRET_KEY"))
	_ = secretKey
}
