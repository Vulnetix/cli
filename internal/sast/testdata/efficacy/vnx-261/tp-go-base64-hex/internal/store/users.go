package store

import (
	"encoding/base64"
	"encoding/hex"
)

type User struct {
	Name     string
	Password string
}

func NewUser(name, password string) User {
~>	return User{Name: name, Password: @@sample:b[a]se[6]4[.][S]td[E]nc[o]di[n]g[.][E]nc[o]de[T]oS[t]ri[n]g@@([]byte(password))}
}

func (u *User) SetPassword(pwd string) {
~>	u.Password = hex.EncodeToString([]byte(pwd))
}
