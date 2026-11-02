package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Client for the Platform IaC config engine, served by vdb-site under
// /api/site/v1/config/*. It is a different backend from the VDB API the rest
// of the CLI talks to (/v2/cli.*), and it takes a different credential: the
// engine changes tenant policy, so it needs an owner or admin. A service
// account's ApiKey is only a member, which is why a vmt_ config management
// token exists.

// configEngineClient calls the engine, over the shared site client.
type configEngineClient struct{ *siteClient }

func newConfigEngineClient(a configAuth) *configEngineClient {
	return &configEngineClient{newSiteClient(a, "config engine")}
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
	// Message says why an external write failed (phase Failed).
	Message string `json:"message,omitempty"`
}

type configAppliedItem struct {
	Kind   string             `json:"kind"`
	Name   string             `json:"name"`
	Action string             `json:"action"`
	Status configObjectStatus `json:"status"`
}

type configApplyResult struct {
	PlanHash string        `json:"planHash"`
	Summary  configSummary `json:"summary"`
	// Failed counts the external objects whose write failed (phase Failed).
	Failed int `json:"failed,omitempty"`
	// Partial is set from the HTTP status: 207 means applied except the
	// objects with phase Failed.
	Partial bool                `json:"-"`
	Items   []configAppliedItem `json:"items"`
}

// configRequest is the JSON body of plan, apply and a draft export.
type configRequest struct {
	Manager   string `json:"manager,omitempty"`
	Prune     bool   `json:"prune,omitempty"`
	SourceRef string `json:"sourceRef,omitempty"`
	PlanHash  string `json:"planHash,omitempty"`
	Documents []any  `json:"documents"`
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
	raw, _, status, err := c.doStatus(ctx, http.MethodPost, "/config/apply", nil, req)
	if err != nil {
		return nil, err
	}
	var r configApplyResult
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("config engine: decode apply result: %w", err)
	}
	r.Partial = status == http.StatusMultiStatus
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

// failedItems are the objects whose write failed.
func (r *configApplyResult) failedItems() []configAppliedItem {
	var out []configAppliedItem
	for _, it := range r.Items {
		if strings.EqualFold(it.Status.Phase, "Failed") {
			out = append(out, it)
		}
	}
	return out
}

// incomplete reports an apply that did not write everything: the server
// answered 207, counted failed objects, or an object's phase is Failed.
func (r *configApplyResult) incomplete() bool {
	return r.Partial || r.Failed > 0 || len(r.failedItems()) > 0
}
