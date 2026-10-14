package auth

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestRejectsNone(t *testing.T) {
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"sub": "x"})
	s, _ := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	parsed, _ := jwt.Parse(s, keyFunc)
	if parsed.Claims != nil && parsed.Valid {
		t.Fatal("none accepted")
	}
	_, _, _ = jwt.NewParser().ParseUnverified(s, jwt.MapClaims{})
}
