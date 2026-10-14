package oidc

import (
	"net/http"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/golang-jwt/jwt/v5"
)

// The issuer picks the key set, so it is read first and the token is
// verified against that issuer's keys before any claim is trusted.
func Verify(r *http.Request) (jwt.MapClaims, error) {
	raw := r.Header.Get("Authorization")
	unverified, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	iss, _ := unverified.Claims.GetIssuer()
	keys := keySetFor(iss)
	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(raw, claims, keys.Keyfunc); err != nil {
		return nil, err
	}
	return claims, nil
}

func VerifyJose(r *http.Request) (*josejwt.Claims, error) {
	tok, err := josejwt.ParseSigned(r.FormValue("id_token"), []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, err
	}
	var peek josejwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&peek); err != nil {
		return nil, err
	}
	var out josejwt.Claims
	if err := tok.Claims(keyFor(peek.Issuer), &out); err != nil {
		return nil, err
	}
	return &out, nil
}
