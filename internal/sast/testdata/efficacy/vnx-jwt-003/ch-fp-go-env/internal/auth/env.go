package auth

import (
	"os"

	"github.com/golang-jwt/jwt/v5"
)

var signingKey = []byte(os.Getenv("JWT_SIGNING_KEY"))

func Sign(c jwt.Claims) (string, error) {
	return jwt.NewWithClaims(@@sample:j[w]t[.][S]ig[n]in[g]Me[t]ho[d]HS[2]56@@, c).SignedString(signingKey)
}
