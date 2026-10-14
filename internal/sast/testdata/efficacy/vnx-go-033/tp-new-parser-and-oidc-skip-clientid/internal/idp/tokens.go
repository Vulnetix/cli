package idp

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
)

~>var parser = jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(issuer))

func verifier(ctx context.Context, provider *oidc.Provider) *oidc.IDTokenVerifier {
	return provider.Verifier(&oidc.Config{
~>		SkipClientIDCheck: true,
	})
}

func check(raw string, kf jwt.Keyfunc) error {
	_, err := parser.Parse(raw, kf)
	return err
}
