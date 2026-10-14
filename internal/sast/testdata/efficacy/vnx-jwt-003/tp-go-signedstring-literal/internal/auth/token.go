package auth

import "github.com/golang-jwt/jwt/v5"

~>var jwtKey = []byte("my_secret_key")

func Issue(user string) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": user})
~>	return t.SignedString([]byte("inline-secret"))
}

func IssueVar(user string) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": user})
	return t.SignedString(jwtKey)
}
