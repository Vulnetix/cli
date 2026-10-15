package tokens

import (
	"github.com/golang-jwt/jwt/v5"
)

// KeyID reads the kid header so the caller can pick the verification key.
// The token is verified afterwards by the JWKS-backed verifier.
func KeyID(raw string) (string, error) {
	tok, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		return "", err
	}
	kid, _ := tok.Header["kid"].(string)
	return kid, nil
}

func Issuer(raw string) (string, error) {
	tok, _, err := new(jwt.Parser).ParseUnverified(raw, &jwt.RegisteredClaims{})
	if err != nil {
		return "", err
	}
	return tok.Claims.GetIssuer()
}
