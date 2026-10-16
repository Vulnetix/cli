package auth

import (
	"net/http"

	"github.com/go-jose/go-jose/v4/jwt"
)

func Claims(w http.ResponseWriter, r *http.Request) (map[string]any, error) {
	tok, err := jwt.ParseSigned(r.Header.Get("X-Token"), []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, err
	}
	var c map[string]any
~>	err = tok.UnsafeClaimsWithoutVerification(&c)
	return c, err
}
