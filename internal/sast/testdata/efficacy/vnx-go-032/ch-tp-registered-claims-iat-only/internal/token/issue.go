package token

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func Issue(userID string, key any) (string, error) {
~>	t := jwt.NewWithClaims(@@sample:j[w]t[.][S]ig[n]in[g]Me[t]ho[d]RS[2]56@@, jwt.RegisteredClaims{
		Subject:  userID,
		Issuer:   "accounts",
		IssuedAt: jwt.NewNumericDate(time.Now()),
	})
	return t.SignedString(key)
}
