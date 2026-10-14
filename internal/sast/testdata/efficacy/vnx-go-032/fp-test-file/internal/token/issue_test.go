package token

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestParsesExpired(t *testing.T) {
	s, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "a"}).SignedString(secret)
	p := jwt.NewParser(jwt.WithoutClaimsValidation())
	if _, err := p.Parse(s, keyFunc); err != nil {
		t.Fatal(err)
	}
}
