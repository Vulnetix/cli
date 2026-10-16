package auth

import (
	"crypto/md5"
	"crypto/sha256"
	"io"
	"os"
)

func FileSum(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := md5.New()
	io.Copy(h, f)
	return h.Sum(nil), nil
}

func KeyID(apiKey string) [32]byte {
	return sha256.Sum256([]byte(apiKey))
}

func ResetFingerprint(resetToken string) [32]byte {
	return sha256.Sum256([]byte(resetToken))
}
