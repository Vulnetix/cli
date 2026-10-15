package auth

import "golang.org/x/crypto/bcrypt"

func Login(u *User, pw string) (*Session, error) {
~>	bcrypt.CompareHashAndPassword(
		[]byte(u.PasswordHash),
		[]byte(pw),
	)
	return newSession(u), nil
}
