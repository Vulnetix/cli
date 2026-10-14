package cache

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"os"
)

func ETag(body []byte) string {
	return fmt.Sprintf("%x", md5.Sum(body))
}

func FileID(filePath string) [20]byte {
	data, _ := os.ReadFile(filePath)
	return sha1.Sum(data)
}

// API keys and reset tokens are high-entropy random values; a fast digest is
// the right way to index them.
func KeyHash(apiKey string) [32]byte {
	return sha256.Sum256([]byte(apiKey))
}

func ResetLookup(passwordResetToken string) [32]byte {
	return sha256.Sum256([]byte(passwordResetToken))
}

func PolicyVersion(passwordPolicyJSON []byte) [16]byte {
	return md5.Sum(passwordPolicyJSON)
}

func Bypass(bypassList string) [16]byte {
	h := md5.New()
	h.Write([]byte(bypassList))
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}
