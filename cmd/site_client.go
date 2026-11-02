package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/vulnetix/cli/v3/pkg/auth"
)

// siteClient calls the Vulnetix console's site API (/api/site/v1/*), which
// vdb-site serves. The config engine (/config/*) and the campaigns routes
// (/campaigns) both live there and take the same credential: a vmt_ token
// from --token or VULNETIX_CONFIG_TOKEN, or whatever the CLI has stored. It is
// a different backend from the VDB API the rest of the CLI talks to
// (/v2/cli.*).

// configTokenEnv holds a config management token (vmt_...) for CI.
const configTokenEnv = "VULNETIX_CONFIG_TOKEN"

// siteBase is the site API base URL. It follows the console base, so
// VULNETIX_WEB_URL points both device login and the engine at a local stack.
func siteBase() string { return webBaseURL() + "/api/site/v1" }

// configAuth is a resolved Authorization header and where it came from.
type configAuth struct {
	Header string
	Source string
}

// resolveConfigAuth picks the credential in the same spirit as
// auth.LoadCredentials: the most explicit source wins. --token, then
// VULNETIX_CONFIG_TOKEN, then whatever the CLI already has stored (a Bearer
// token or an ApiKey). The stored credential is a fallback for people at a
// terminal; whether the engine accepts it depends on the caller's role.
func resolveConfigAuth(flagToken string) (configAuth, error) {
	if t := strings.TrimSpace(flagToken); t != "" {
		return configAuth{Header: "Bearer " + t, Source: "--token"}, nil
	}
	if t := strings.TrimSpace(os.Getenv(configTokenEnv)); t != "" {
		return configAuth{Header: "Bearer " + t, Source: configTokenEnv}, nil
	}
	creds, err := auth.LoadCredentials()
	if err != nil {
		return configAuth{}, fmt.Errorf("no config credential: pass --token, set %s, or run 'vulnetix auth login': %w", configTokenEnv, err)
	}
	h := auth.GetAuthHeader(creds)
	if h == "" {
		return configAuth{}, fmt.Errorf("the stored credential (%s) cannot authenticate to the config engine; pass --token or set %s", creds.Method, configTokenEnv)
	}
	return configAuth{Header: h, Source: auth.CredentialSource()}, nil
}

// siteClient is an authenticated client for the site API.
type siteClient struct {
	BaseURL string
	Auth    configAuth
	HTTP    *http.Client
	// Label prefixes errors ("config engine", "campaigns").
	Label string
}

func newSiteClient(a configAuth, label string) *siteClient {
	return &siteClient{BaseURL: siteBase(), Auth: a, HTTP: &http.Client{Timeout: 120 * time.Second}, Label: label}
}

// Get fetches path (relative to the site API base) with query. It satisfies
// the small interface internal/campaigns reads through.
func (c *siteClient) Get(ctx context.Context, path string, query url.Values) ([]byte, error) {
	out, _, err := c.do(ctx, http.MethodGet, path, query, nil)
	return out, err
}

// configHTTPError is a non-2xx answer from the engine. Body is kept because a
// 409 or 422 carries the fresh plan.
type configHTTPError struct {
	Status  int
	Code    string // the "error" field
	Message string // "message", or "error" when there is no message
	Body    []byte
	Label   string // who answered; defaults to "config engine"
}

func (e *configHTTPError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	label := e.Label
	if label == "" {
		label = "config engine"
	}
	return fmt.Sprintf("%s: HTTP %d: %s", label, e.Status, msg)
}

func (c *siteClient) do(ctx context.Context, method, path string, query url.Values, body any) ([]byte, http.Header, error) {
	out, hdr, _, err := c.doStatus(ctx, method, path, query, body)
	return out, hdr, err
}

// doStatus is do that also returns the HTTP status of a 2xx answer, for the
// calls where 200 and 207 mean different things.
func (c *siteClient) doStatus(ctx context.Context, method, path string, query url.Values, body any) ([]byte, http.Header, int, error) {
	u := strings.TrimRight(c.BaseURL, "/") + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, nil, 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "vulnetix-cli/"+version)
	if c.Auth.Header != "" {
		req.Header.Set("Authorization", c.Auth.Header)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, nil, 0, fmt.Errorf(c.Label+": %w", err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, nil, 0, fmt.Errorf(c.Label+": read response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		he := &configHTTPError{Status: resp.StatusCode, Body: out, Label: c.Label}
		var e struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if json.Unmarshal(out, &e) == nil {
			he.Code, he.Message = e.Error, e.Message
			if he.Message == "" {
				he.Message = e.Error
			}
		}
		return nil, nil, resp.StatusCode, he
	}
	return out, resp.Header, resp.StatusCode, nil
}
