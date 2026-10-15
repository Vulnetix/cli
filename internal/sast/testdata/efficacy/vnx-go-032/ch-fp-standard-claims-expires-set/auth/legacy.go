package auth

import (
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

func legacyToken(uid string) (string, error) {
	std := jwt.StandardClaims{Subject: uid, Issuer: "legacy"}
	std.ExpiresAt = time.Now().Add(time.Hour).Unix()
	return jwt.NewWithClaims(@@sample:j[w]t[.][S]ig[n]in[g]Me[t]ho[d]HS[2]56@@, std).SignedString(secret)
}

func fromHelper(u User) (string, error) {
	return jwt.NewWithClaims(@@sample:j[w]t[.][S]ig[n]in[g]Me[t]ho[d]HS[2]56@@, claimsFor(u)).SignedString(secret)
}
