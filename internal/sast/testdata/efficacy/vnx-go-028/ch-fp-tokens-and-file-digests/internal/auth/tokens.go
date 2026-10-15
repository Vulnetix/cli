package auth

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"os"
)

func tokenDigest(resetToken string) string {
	sum := sha256.Sum256([]byte(resetToken))
	return hex.EncodeToString(sum[:])
}

func apiKeyLookup(apiKey string) [32]byte {
	return sha256.Sum256([]byte(apiKey))
}

func fileETag(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(md5.New().Sum(b)), nil
}

func passwordResetKey(email string) [32]byte {
	return sha256.Sum256([]byte(email))
}
