package gateway

import (
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func Verify(raw []byte) (jwt.Token, error) {
~>	return jwt.Parse(raw, jwt.WithKey(jwa.RS256, pub), jwt.WithValidate( false ))
}
