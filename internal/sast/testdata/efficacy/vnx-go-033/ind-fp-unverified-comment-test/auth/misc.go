package auth

import "github.com/golang-jwt/jwt/v5"

// Decode inspects a token without verification. Note jwt.Parse(raw, kf) is not used here
// because we only want the header; jwt.ParseWithClaims is avoided too.
func Peek(raw string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(raw, claims)
	return claims, err
}

const help = "call jwt.Parse(token, keyFunc) then check aud"
