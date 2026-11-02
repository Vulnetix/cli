package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/vulnetix/cli/v3/pkg/auth"
)

// Client for the Platform IaC config engine, served by vdb-site under
// /api/site/v1/config/*. It is a different backend from the VDB API the rest
// of the CLI talks to (/v2/cli.*), and it takes a different credential: the
// engine changes tenant policy, so it needs an owner or admin. A service
// account's ApiKey is only a member, which is why a vmt_ config management
// token exists.

// configTokenEnv holds a config management token (vmt_...) for CI.
const configTokenEnv = "VULNETIX_CONFIG_TOKEN"

// configEngineBase is the engine's base URL. It follows the console base, so
// VULNETIX_WEB_URL points both device login and the engine at a local stack.
func configEngineBase() string { return webBaseURL() + "/api/site/v1" }

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

// configEngineClient calls the engine.
type configEngineClient struct {
	BaseURL string
	Auth    configAuth
	HTTP    *http.Client
}

func newConfigEngineClient(a configAuth) *configEngineClient {
	return &configEngineClient{BaseURL: configEngineBase(), Auth: a, HTTP: &http.Client{Timeout: 120 * time.Second}}
}

// configHTTPError is a non-2xx answer from the engine. Body is kept because a
// 409 or 422 carries the fresh plan.
type configHTTPError struct {
	Status  int
	Code    string // the "error" field
	Message string // "message", or "error" when there is no message
	Body    []byte
}

func (e *configHTTPError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	return fmt.Sprintf("config engine: HTTP %d: %s", e.Status, msg)
}

// Wire types: the JSON vdb-site's internal/config engine returns.

type configFieldChange struct {
	Path string `json:"path"`
	From any    `json:"from"`
	To   any    `json:"to"`
}

type configPlanItem struct {
	Kind    string              `json:"kind"`
	Name    string              `json:"name"`
	Action  string              `json:"action"` // create | update | delete | noop
	Changes []configFieldChange `json:"changes"`
	Manager string              `json:"manager,omitempty"`
	Adopt   bool                `json:"adopt,omitempty"`
	Drift   bool                `json:"drift,omitempty"`
}

type configCondition struct {
	Code    string `json:"code"`
	Kind    string `json:"kind,omitempty"`
	Name    string `json:"name,omitempty"`
	Message string `json:"message"`
}

type configSummary struct {
	Create int `json:"create"`
	Update int `json:"update"`
	Delete int `json:"delete"`
	Noop   int `json:"noop"`
}

type configPlan struct {
	Tenant   string            `json:"tenant"`
	Manager  string            `json:"manager"`
	Prune    bool              `json:"prune"`
	Items    []configPlanItem  `json:"items"`
	Blocking []configCondition `json:"blocking"`
	Warnings []configCondition `json:"warnings"`
	Summary  configSummary     `json:"summary"`
	PlanHash string            `json:"planHash"`
}

// needsApply reports whether apply would do anything: change an object, or
// record ownership of one that exists unowned or drifted.
func (p *configPlan) needsApply() bool {
	if p.Summary.Create+p.Summary.Update+p.Summary.Delete > 0 {
		return true
	}
	for _, it := range p.Items {
		if it.Adopt || it.Drift {
			return true
		}
	}
	return false
}

type configObjectStatus struct {
	Phase       string `json:"phase"`
	ObjectUUID  string `json:"objectUuid,omitempty"`
	Manager     string `json:"manager,omitempty"`
	AppliedHash string `json:"appliedHash,omitempty"`
	AppliedAt   int64  `json:"appliedAt,omitempty"`
}

type configAppliedItem struct {
	Kind   string             `json:"kind"`
	Name   string             `json:"name"`
	Action string             `json:"action"`
	Status configObjectStatus `json:"status"`
}

type configApplyResult struct {
	PlanHash string              `json:"planHash"`
	Summary  configSummary       `json:"summary"`
	Items    []configAppliedItem `json:"items"`
}

// configRequest is the JSON body of plan, apply and a draft export.
type configRequest struct {
	Manager   string `json:"manager,omitempty"`
	Prune     bool   `json:"prune,omitempty"`
	SourceRef string `json:"sourceRef,omitempty"`
	PlanHash  string `json:"planHash,omitempty"`
	Documents []any  `json:"documents"`
}

func (c *configEngineClient) do(ctx context.Context, method, path string, query url.Values, body any) ([]byte, http.Header, error) {
	u := strings.TrimRight(c.BaseURL, "/") + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, nil, err
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
		return nil, nil, fmt.Errorf("config engine: %w", err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("config engine: read response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		he := &configHTTPError{Status: resp.StatusCode, Body: out}
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
		return nil, nil, he
	}
	return out, resp.Header, nil
}

// Plan asks the engine what applying docs would do. The raw body is returned
// too, so -o json can print exactly what the server said.
func (c *configEngineClient) Plan(ctx context.Context, req configRequest) (*configPlan, []byte, error) {
	raw, _, err := c.do(ctx, http.MethodPost, "/config/plan", nil, req)
	if err != nil {
		return nil, nil, err
	}
	var p configPlan
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, nil, fmt.Errorf("config engine: decode plan: %w", err)
	}
	return &p, raw, nil
}

// Apply applies the plan named by req.PlanHash.
func (c *configEngineClient) Apply(ctx context.Context, req configRequest) (*configApplyResult, error) {
	raw, _, err := c.do(ctx, http.MethodPost, "/config/apply", nil, req)
	if err != nil {
		return nil, err
	}
	var r configApplyResult
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("config engine: decode apply result: %w", err)
	}
	return &r, nil
}

// Export renders the tenant's state (docs == nil) or a draft of docs.
func (c *configEngineClient) Export(ctx context.Context, query url.Values, docs []any) ([]byte, error) {
	if docs == nil {
		out, _, err := c.do(ctx, http.MethodGet, "/config/export", query, nil)
		return out, err
	}
	out, _, err := c.do(ctx, http.MethodPost, "/config/export", query, configRequest{Documents: docs})
	return out, err
}

// planFromHTTPError extracts the fresh plan a 409 or 422 carries.
func planFromHTTPError(err error) *configPlan {
	var he *configHTTPError
	if !errors.As(err, &he) {
		return nil
	}
	var body struct {
		Plan *configPlan `json:"plan"`
	}
	if json.Unmarshal(he.Body, &body) != nil {
		return nil
	}
	return body.Plan
}
