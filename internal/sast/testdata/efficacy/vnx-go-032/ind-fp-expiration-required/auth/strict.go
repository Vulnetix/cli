package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var strict = jwt.NewParser(jwt.WithExpirationRequired(), jwt.WithLeeway(30*time.Second))

func Parse(raw string) (*jwt.Token, error) {
	return strict.Parse(raw, keyFunc)
}
