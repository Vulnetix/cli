package auth

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestRejectsNone(t *testing.T) {
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"sub": "admin"})
	raw, _ := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if _, err := Verify(raw); err == nil {
		t.Fatal("unsigned token accepted")
	}
}
