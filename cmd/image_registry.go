package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/vulnetix/cli/v4/internal/imagesrc"
	"github.com/vulnetix/cli/v4/pkg/auth"
)

// The organisation's own registry connection for `vulnetix image`.
//
// A signed in run asks the site API (vdb-site, POST /scan-registries/oci-token)
// for a short-lived pull token for the one repository it is about to read. The
// stored login never leaves Vulnetix: the answer is the registry's own token,
// which the registry expires in minutes, for that repository only. Vulnetix
// answers only for a host and repository the caller's organisation has
// connected; for anything else (and for a registry with no token service) the
// run uses the user's docker credentials as it always did.
//
// The request names the registry and repository, so a run that must send
// nothing to Vulnetix (--no-upload) and a community run (no account) do not
// make it.

// imageTenantTokens returns the token source for this run, or nil when the run
// must not ask: no upload was requested, there is no signed in account, or the
// credential cannot authenticate to the site API.
func imageTenantTokens(noUpload bool) imagesrc.TokenSource {
	if noUpload || vdbCreds == nil || vdbCommunityMode {
		return nil
	}
	h := auth.GetAuthHeader(vdbCreds)
	if h == "" {
		return nil
	}
	return siteOCITokens{c: newSiteClient(configAuth{Header: h, Source: "image"}, "registry connection")}
}

// siteOCITokens asks the site API for registry pull tokens.
type siteOCITokens struct{ c *siteClient }

// ociTokenTimeout bounds the ask, so a slow site never stalls a pull that the
// user's own credentials could do.
const ociTokenTimeout = 20 * time.Second

// OCIToken implements imagesrc.TokenSource.
func (s siteOCITokens) OCIToken(ctx context.Context, registry, repository string) (*imagesrc.TenantToken, error) {
	ctx, cancel := context.WithTimeout(ctx, ociTokenTimeout)
	defer cancel()
	raw, _, err := s.c.do(ctx, http.MethodPost, "/scan-registries/oci-token", nil, map[string]string{"registry": registry, "repository": repository})
	if err != nil {
		var he *configHTTPError
		if !errors.As(err, &he) {
			return nil, err
		}
		var body struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(he.Body, &body)
		switch {
		case he.Status == http.StatusUnauthorized, body.Code == "no_connection", body.Code == "plan_locked", body.Code == "forbidden":
			return nil, imagesrc.ErrNoConnection
		case body.Code == "no_ephemeral_credential":
			return nil, imagesrc.ErrNoEphemeral
		}
		// The text is the API's message for the status; it carries no credential.
		return nil, fmt.Errorf("HTTP %d %s: %s", he.Status, body.Code, he.Message)
	}
	var out struct {
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expiresAt"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Token == "" {
		return nil, errors.New("the answer had no token")
	}
	exp := time.Now().Add(time.Minute)
	if out.ExpiresAt > 0 {
		exp = time.UnixMilli(out.ExpiresAt)
	}
	return &imagesrc.TenantToken{Token: out.Token, ExpiresAt: exp}, nil
}
