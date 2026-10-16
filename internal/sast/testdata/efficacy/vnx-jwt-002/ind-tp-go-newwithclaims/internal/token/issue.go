package token

import "github.com/golang-jwt/jwt/v5"

func Issue(uid string, key []byte) (string, error) {
~>	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": uid,
		"adm": false,
	})
	return t.SignedString(key)
}
