// Package campaigns reads Vulnetix remediation campaigns from the console's
// site API (GET /api/site/v1/campaigns), the source of the GitHub security
// campaigns that `vulnetix gha publish campaigns` creates.
//
// The routes are Pro. A caller who is not entitled gets HTTP 200 with a marker
// body ({"planLocked": true, ...}) instead of an error so the console can show
// an upgrade prompt; that is surfaced here as ErrNotEntitled. A vmt_ token
// needs the "campaigns" read scope.
package campaigns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// Getter fetches a path under the site API and returns the body. The CLI's
// siteClient implements it, so credentials and the base URL stay in one place.
type Getter interface {
	Get(ctx context.Context, path string, query url.Values) ([]byte, error)
}

// ErrNotEntitled is returned when the organization is not on a plan with
// campaigns.
var ErrNotEntitled = errors.New("campaigns need a Pro plan (the organization is not entitled)")

// Status values of a campaign.
const (
	StatusActive    = "ACTIVE"
	StatusCompleted = "COMPLETED"
	StatusArchived  = "ARCHIVED"
)

// Campaign is a Vulnetix remediation campaign.
type Campaign struct {
	UUID        string `json:"uuid"`
	Name        string `json:"name"`
	Description string `json:"description"`
	TargetKind  string `json:"targetKind"`
	Status      string `json:"status"`
	// DeadlineAt is epoch milliseconds, absent when the campaign has none.
	DeadlineAt  *int64          `json:"deadlineAt"`
	CohortSize  int             `json:"cohortSize"`
	ClosedCount int             `json:"closedCount"`
	Scope       json.RawMessage `json:"scope"`
	CompletedAt *int64          `json:"completedAt"`
	ArchivedAt  *int64          `json:"archivedAt"`
}

// Closed reports whether the campaign is over: completed or archived.
func (c Campaign) Closed() bool {
	return c.Status == StatusCompleted || c.Status == StatusArchived || c.ArchivedAt != nil
}

// Deadline returns the deadline, and false when the campaign has none.
func (c Campaign) Deadline() (time.Time, bool) {
	if c.DeadlineAt == nil || *c.DeadlineAt <= 0 {
		return time.Time{}, false
	}
	return time.UnixMilli(*c.DeadlineAt).UTC(), true
}

// Item is one member of a campaign's frozen cohort.
type Item struct {
	UUID             string `json:"uuid"`
	ItemKey          string `json:"itemKey"`
	Kind             string `json:"kind"` // finding or dependency
	RepoName         string `json:"repoName"`
	FindingID        string `json:"findingId"`
	Category         string `json:"category"`
	PackageName      string `json:"packageName"`
	PackageVersion   string `json:"packageVersion"`
	PackageEcosystem string `json:"packageEcosystem"`
	DependencyKey    string `json:"dependencyKey"`
	Severity         string `json:"severity"`
	State            string `json:"state"` // open or done
}

// Client reads campaigns.
type Client struct {
	Site Getter
	// PerPage is the items page size (the API caps it at 200).
	PerPage int
}

// New returns a client over site.
func New(site Getter) *Client { return &Client{Site: site, PerPage: 200} }

// locked reports the not-entitled marker body.
func locked(raw []byte) bool {
	var m struct {
		PlanLocked bool `json:"planLocked"`
	}
	return json.Unmarshal(raw, &m) == nil && m.PlanLocked
}

// List returns the organization's campaigns, newest first. Archived ones are
// included when includeArchived is set, so a GitHub campaign can be closed for
// a Vulnetix campaign that has since been archived.
func (c *Client) List(ctx context.Context, includeArchived bool) ([]Campaign, error) {
	q := url.Values{}
	if includeArchived {
		q.Set("includeArchived", "true")
	}
	raw, err := c.Site.Get(ctx, "/campaigns", q)
	if err != nil {
		return nil, fmt.Errorf("list campaigns: %w", err)
	}
	if locked(raw) {
		return nil, ErrNotEntitled
	}
	var body struct {
		Campaigns []Campaign `json:"campaigns"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("list campaigns: decode: %w", err)
	}
	return body.Campaigns, nil
}

// Items returns the campaign's cohort items in the given state ("open",
// "done", or "" for all), following pagination.
func (c *Client) Items(ctx context.Context, id, state string) ([]Item, error) {
	per := c.PerPage
	if per <= 0 || per > 200 {
		per = 200
	}
	var out []Item
	for page := 1; ; page++ {
		q := url.Values{}
		q.Set("page", strconv.Itoa(page))
		q.Set("perPage", strconv.Itoa(per))
		if state != "" {
			q.Set("state", state)
		}
		raw, err := c.Site.Get(ctx, "/campaigns/"+url.PathEscape(id)+"/items", q)
		if err != nil {
			return nil, fmt.Errorf("campaign %s items: %w", id, err)
		}
		if locked(raw) {
			return nil, ErrNotEntitled
		}
		var body struct {
			Items      []Item `json:"items"`
			Pagination struct {
				TotalPages int `json:"totalPages"`
			} `json:"pagination"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			return nil, fmt.Errorf("campaign %s items: decode: %w", id, err)
		}
		out = append(out, body.Items...)
		if page >= body.Pagination.TotalPages || len(body.Items) == 0 {
			return out, nil
		}
	}
}
