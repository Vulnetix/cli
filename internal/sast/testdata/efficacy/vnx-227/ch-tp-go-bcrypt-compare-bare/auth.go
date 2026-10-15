package auth

import "golang.org/x/crypto/bcrypt"

func Login(user *User, password string) (*Session, error) {
~>	bcrypt.CompareHashAndPassword(user.Hash, []byte(password))
	return newSession(user), nil
}
