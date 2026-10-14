package sso

import (
	"net/http"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type idClaims struct {
	Email string `json:"email"`
	jwt.Claims
}

func Callback(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("id_token")
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		http.Error(w, "bad token", http.StatusBadRequest)
		return
	}
	var c idClaims
~>	if err := tok.UnsafeClaimsWithoutVerification(&c); err != nil {
		http.Error(w, "bad claims", http.StatusBadRequest)
		return
	}
	startSession(w, c.Email)
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	tok, err := jwt.ParseSigned(r.Header.Get("X-Id-Token"), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return
	}
	var c idClaims
~>	tok.Claims(providerKey, &c)
	startSession(w, c.Email)
}
