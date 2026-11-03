package ghactx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/vulnetix/cli/v4/pkg/vdb"
)

// OIDCAudience is the audience vdb-api checks on a GitHub Actions id token.
const OIDCAudience = "vulnetix"

// oidcTimeout bounds the one token request. A slow token service costs the
// identity evidence, never the command.
const oidcTimeout = 5 * time.Second

var (
	oidcOnce  sync.Once
	oidcToken string
)

// OIDCToken returns the runner's OIDC id token for audience "vulnetix", asked
// for once per process. It is "" outside GitHub Actions, in a workflow without
// `permissions: id-token: write`, and whenever the request fails. Failures are
// silent except under --verbose, and the token is never logged.
func OIDCToken() string {
	oidcOnce.Do(func() {
		oidcToken = fetchOIDCToken(context.Background(), http.DefaultClient,
			os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))
	})
	return oidcToken
}

// fetchOIDCToken performs the request GitHub documents for custom audiences:
// GET $ACTIONS_ID_TOKEN_REQUEST_URL&audience=<aud> with the request token as a
// bearer credential, answered by {"value": "<jwt>"}.
func fetchOIDCToken(ctx context.Context, client *http.Client, requestURL, requestToken string) string {
	if requestURL == "" || requestToken == "" {
		return ""
	}
	u, err := url.Parse(requestURL)
	if err != nil {
		debugf("oidc: request url does not parse")
		return ""
	}
	q := u.Query()
	q.Set("audience", OIDCAudience)
	u.RawQuery = q.Encode()

	ctx, cancel := context.WithTimeout(ctx, oidcTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		debugf("oidc: %v", err)
		return ""
	}
	req.Header.Set("Authorization", "bearer "+requestToken)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		// The error text can include the URL, which carries no secret; the
		// request token travels in the header only.
		debugf("oidc: token request failed: %v", err)
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		debugf("oidc: reading token response: %v", err)
		return ""
	}
	if resp.StatusCode != http.StatusOK {
		debugf("oidc: token service answered HTTP %d", resp.StatusCode)
		return ""
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		debugf("oidc: token response is not JSON")
		return ""
	}
	return strings.TrimSpace(out.Value)
}

func debugf(format string, args ...any) {
	if vdb.Verbose {
		fmt.Fprintf(os.Stderr, "  "+format+"\n", args...)
	}
}
