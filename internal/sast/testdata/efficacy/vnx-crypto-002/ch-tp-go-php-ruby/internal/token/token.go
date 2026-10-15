package token

import (
	"crypto/sha1"
	"fmt"
)

func Make(secret, user string) string {
~>	return fmt.Sprintf("%x", sha1.Sum([]byte(secret+user)))
}
