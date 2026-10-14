package auth

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	jwtv4 "github.com/golang-jwt/jwt/v4"
)

~>var parser = jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}), jwt.WithoutClaimsValidation())

func Claims(r *http.Request) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	_, err := parser.ParseWithClaims(r.Header.Get("Authorization"), claims, publicKey)
	return claims, err
}

func ClaimsV4(r *http.Request) (jwtv4.MapClaims, error) {
	p := &jwtv4.Parser{
		ValidMethods:         []string{"RS256"},
~>		SkipClaimsValidation: true,
	}
	claims := jwtv4.MapClaims{}
	_, err := p.ParseWithClaims(r.Header.Get("Authorization"), claims, publicKeyV4)
	return claims, err
}

func legacy(raw string) error {
	_, err := jwt.Parse(raw, publicKey,
~>		jwt.WithoutClaimsValidation(),
	)
	return err
}
