package models

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
)

type User struct {
	Name         string
	PasswordHash string
}

func NewUser(name, secret string) *User {
	u := &User{Name: name}
~>	u.PasswordHash = fmt.Sprintf("%x", md5.Sum([]byte(secret)))
	return u
}

func (u *User) SetSecret(plain string) {
~>	hashedPassword := sha1.Sum([]byte(plain))
	u.PasswordHash = hex.EncodeToString(hashedPassword[:])
}
