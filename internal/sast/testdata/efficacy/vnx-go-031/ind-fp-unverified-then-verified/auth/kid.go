package auth

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

func Authn(w http.ResponseWriter, r *http.Request) {
	raw := r.Header.Get("Authorization")
	hdr := jwt.MapClaims{}
	unverified, _, err := jwt.NewParser().ParseUnverified(raw, hdr)
	if err != nil {
		http.Error(w, "bad", 401)
		return
	}
	key := lookupKey(unverified.Header["kid"])
	tok, err := jwt.ParseWithClaims(raw, jwt.MapClaims{}, func(*jwt.Token) (any, error) { return key, nil })
	if err != nil || !tok.Valid {
		http.Error(w, "bad", 401)
	}
}
