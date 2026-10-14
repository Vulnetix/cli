package token

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type SessionClaims struct {
	UserID string `json:"uid"`
	Admin  bool   `json:"adm"`
	jwt.RegisteredClaims
}

func Issue(userID string) (string, error) {
~>	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  userID,
		"role": "user",
		"iat":  time.Now().Unix(),
	}).SignedString(secret)
}

func IssueSession(userID string, admin bool) (string, error) {
	claims := SessionClaims{
		UserID: userID,
		Admin:  admin,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   "api",
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}
~>	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(secret)
}

func IssueLegacy(name string) string {
~>	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["name"] = name
	claims["admin"] = true
	s, _ := token.SignedString(secret)
	return s
}
