package auth

import "github.com/golang-jwt/jwt/v5"

func Issue(userID string, key []byte) (string, error) {
~>	token := jwt.NewWithClaims(@@sample:j[w]t[.][S]ig[n]in[g]Me[t]ho[d]HS[2]56@@, jwt.MapClaims{"sub": userID, "admin": false})
	return token.SignedString(key)
}
