package auth

import "github.com/golang-jwt/jwt/v5"

~>var jwtKey = []byte("@@sample:m[y][_]s[e]cr[e]t[_][k]ey[_]12[3]@@")

func Sign(claims jwt.Claims) (string, error) {
	return jwt.NewWithClaims(@@sample:j[w]t[.][S]ig[n]in[g]Me[t]ho[d]HS[2]56@@, claims).SignedString(jwtKey)
}
