package auth

import (
	"crypto/sha256"
	"fmt"
)

func Digest(user, passwd string) string {
	h := sha256.New()
~>	h.Write([]byte(user + ":" + passwd))
	return fmt.Sprintf("%x", h.Sum(nil))
}
