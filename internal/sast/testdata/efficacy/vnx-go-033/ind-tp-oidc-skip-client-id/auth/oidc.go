package auth

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
)

func NewVerifier(ctx context.Context, issuer string) (*oidc.IDTokenVerifier, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
~>	return provider.Verifier(&oidc.Config{SkipClientIDCheck: true}), nil
}
