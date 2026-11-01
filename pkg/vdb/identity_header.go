package vdb

import (
	"net/http"
	"strings"
)

// GHAOIDCHeader carries a GitHub Actions OIDC id token (audience "vulnetix").
// vdb-api verifies it against GitHub's JWKS and ranks it above every claim in
// CliEnv.Identity.
const GHAOIDCHeader = "X-Vulnetix-GHA-OIDC"

// GHAOIDCToken returns the runner's OIDC token, or "" outside a runner that
// grants one. The cmd layer sets it to ghactx.OIDCToken; it lives here as a
// variable because internal/ghactx imports this package.
var GHAOIDCToken func() string

// setIdentityHeaders adds the identity evidence headers to a /v2/cli.* request.
// Called from addAuthHeader so every send and every retry carries them.
func setIdentityHeaders(req *http.Request) {
	if req == nil || req.URL == nil || GHAOIDCToken == nil {
		return
	}
	if !strings.Contains(req.URL.Path, "/cli.") {
		return
	}
	if tok := GHAOIDCToken(); tok != "" {
		req.Header.Set(GHAOIDCHeader, tok)
	}
}
