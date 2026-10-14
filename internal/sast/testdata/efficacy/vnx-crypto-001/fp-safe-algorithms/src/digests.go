package digests

import (
	"crypto/sha256"
	"encoding/hex"
)

func Sum(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}
