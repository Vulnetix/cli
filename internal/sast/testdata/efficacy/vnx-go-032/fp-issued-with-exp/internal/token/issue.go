package token

import (
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/golang-jwt/jwt/v5"
)

type SessionClaims struct {
	UserID string `json:"uid"`
	jwt.RegisteredClaims
}

func Issue(userID string) (string, error) {
	now := time.Now()
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": userID,
		"iat": now.Unix(),
		"exp": now.Add(15 * time.Minute).Unix(),
	}).SignedString(secret)
}

func IssueSession(userID string) (string, error) {
	claims := SessionClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

func IssueLegacy(name string) string {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["name"] = name
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	s, _ := token.SignedString(secret)
	return s
}

func Mint(sig jose.Signer, subject string) (string, error) {
	cl := josejwt.Claims{
		Subject: subject,
		Expiry:  josejwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
	}
	return josejwt.Signed(sig).Claims(cl).Serialize()
}
