package auth

import (
	"time"

	jwx "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/golang-jwt/jwt/v5"
)

var parser = jwt.NewParser(jwt.WithExpirationRequired(), jwt.WithLeeway(30*time.Second))

func Parse(raw string) (*jwt.Token, error) {
	return parser.Parse(raw, keyFunc)
}

func ParseJWX(raw []byte) (jwx.Token, error) {
	return jwx.Parse(raw, jwx.WithKey(alg, pub), jwx.WithValidate(true))
}

// Claims come from a constructor that sets the expiry for every token.
func Issue(u User) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodES256, newClaims(u, time.Hour)).SignedString(priv)
}

func Reissue(c *SessionClaims) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, c)
	return tok.SignedString(priv)
}
