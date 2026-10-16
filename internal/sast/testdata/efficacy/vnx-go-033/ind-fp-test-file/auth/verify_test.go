package auth

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestParse(t *testing.T) {
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "x"})
	s, _ := tok.SignedString([]byte("k"))
	if _, err := jwt.Parse(s, func(*jwt.Token) (interface{}, error) { return []byte("k"), nil }); err != nil {
		t.Fatal(err)
	}
}
