package kms

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
)

// Verify checks the signature; the caller supplies the claim checks.
func (v *Verifier) Verify(ctx context.Context, raw string, claims jwt.Claims, opts ...jwt.ParserOption) error {
	_, err := jwt.ParseWithClaims(raw, claims, v.keyFunc(ctx), opts...)
	return err
}
