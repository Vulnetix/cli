package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func Issue(id string, key []byte) (string, error) {
	claims := jwt.MapClaims{"sub": id}
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	return jwt.NewWithClaims(@@sample:j[w]t[.][S]ig[n]in[g]Me[t]ho[d]HS[2]56@@, claims).SignedString(key)
}
