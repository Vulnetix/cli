package users

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
)

func HashPassword(password string) string {
~>	sum := md5.Sum([]byte(password))
	return hex.EncodeToString(sum[:])
}

func (u *User) Fingerprint() string {
~>	return fmt.Sprintf("%x", md5.Sum([]byte(u.Salt+u.Password)))
}

type User struct{ Salt, Password string }
