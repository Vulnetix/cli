package auth

import (
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func Parse(raw []byte, key interface{}) (jwt.Token, error) {
	return jwt.Parse(raw, jwt.WithKey(jwa.RS256, key), jwt.WithVerify(true))
}
