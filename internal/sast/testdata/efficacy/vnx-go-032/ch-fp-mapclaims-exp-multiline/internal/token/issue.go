package token

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func Issue(userID, role string) (string, error) {
	claims := jwt.MapClaims{
		"sub":  userID,
		"role": role,
		"iat":  time.Now().Unix(),
		"exp": time.Now().
			Add(15 * time.Minute).
			Unix(),
	}
	return jwt.NewWithClaims(@@sample:j[w]t[.][S]ig[n]in[g]Me[t]ho[d]HS[2]56@@, claims).SignedString(key)
}
