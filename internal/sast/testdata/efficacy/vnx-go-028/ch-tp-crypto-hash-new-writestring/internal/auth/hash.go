package auth

import (
	"crypto"
	_ "crypto/sha256"
	"encoding/hex"
	"io"
)

func HashPassword(newPassword string) string {
	h := crypto.SHA256.New()
~>	io.WriteString(h, newPassword)
	return hex.EncodeToString(h.Sum(nil))
}
