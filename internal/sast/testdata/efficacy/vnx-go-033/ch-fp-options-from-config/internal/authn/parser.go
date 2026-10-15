package authn

import "github.com/golang-jwt/jwt/v5"

type Config struct {
	Options []jwt.ParserOption
}

// NewVerifier builds the parser from options assembled by config.Load,
// which always appends jwt.WithAudience for the configured client.
func NewVerifier(cfg Config) *jwt.Parser {
	return jwt.NewParser(cfg.Options...)
}

var description = "use jwt.Parse(token, keyFunc) with jwt.WithAudience"
