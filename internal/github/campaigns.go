package github

// GitHub security campaigns: GET/POST /orgs/{org}/campaigns and
// PATCH /orgs/{org}/campaigns/{campaign_number}, plus the repository code
// scanning alert listing campaigns are built from.
//
// Campaigns need GitHub Advanced Security and a token that is an organization
// owner or security manager (a PAT or a GitHub App); the workflow GITHUB_TOKEN
// cannot manage them. The alerts of a campaign cannot be changed after it is
// created, so a changed scope means closing the campaign and creating another.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Limits GitHub puts on a campaign.
const (
	CampaignNameMax        = 50
	CampaignDescriptionMax = 255
	// CampaignAlertsMax is the most alerts one campaign can hold.
	CampaignAlertsMax = 1000
)

// Campaign states.
const (
	CampaignOpen   = "open"
	CampaignClosed = "closed"
)

// Campaign is a GitHub security campaign as listed.
type Campaign struct {
	Number      int    `json:"number"`
	Name        string `json:"name"`
	Description string `json:"description"`
	State       string `json:"state"`
	EndsAt      string `json:"ends_at"`
	ContactLink string `json:"contact_link"`
	HTMLURL     string `json:"html_url"`
}

// CampaignAlerts names the code scanning alerts of one repository.
type CampaignAlerts struct {
	RepositoryID int   `json:"repository_id"`
	AlertNumbers []int `json:"alert_numbers"`
}

// CampaignCreate is the create body.
type CampaignCreate struct {
	Name               string           `json:"name"`
	Description        string           `json:"description"`
	EndsAt             string           `json:"ends_at"`
	ContactLink        string           `json:"contact_link,omitempty"`
	CodeScanningAlerts []CampaignAlerts `json:"code_scanning_alerts"`
	GenerateIssues     bool             `json:"generate_issues"`
}

// CampaignPatch is the update body. Empty fields are left out and so stay as
// they are.
type CampaignPatch struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	EndsAt      string `json:"ends_at,omitempty"`
	ContactLink string `json:"contact_link,omitempty"`
	State       string `json:"state,omitempty"`
}

// ListCampaigns returns the organization's campaigns, open and closed.
func (c *Client) ListCampaigns(ctx context.Context, org string) ([]Campaign, error) {
	var out []Campaign
	err := c.GetAll(ctx, fmt.Sprintf("/orgs/%s/campaigns?per_page=100", url.PathEscape(org)), &out)
	return out, err
}

// CreateCampaign creates a campaign.
func (c *Client) CreateCampaign(ctx context.Context, org string, req CampaignCreate) (*Campaign, error) {
	var out Campaign
	if _, err := c.Do(ctx, http.MethodPost, fmt.Sprintf("/orgs/%s/campaigns", url.PathEscape(org)), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PatchCampaign updates a campaign by its number.
func (c *Client) PatchCampaign(ctx context.Context, org string, number int, req CampaignPatch) (*Campaign, error) {
	var out Campaign
	if _, err := c.Do(ctx, http.MethodPatch, fmt.Sprintf("/orgs/%s/campaigns/%d", url.PathEscape(org), number), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

var campaignMarker = regexp.MustCompile(`<!-- vulnetix-campaign:([0-9a-fA-F-]{8,}) -->`)

// CampaignMarker is the line that ties a GitHub campaign to the Vulnetix
// campaign it was made from.
func CampaignMarker(uuid string) string {
	return "<!-- vulnetix-campaign:" + uuid + " -->"
}

// CampaignMarkerOf returns the Vulnetix campaign uuid in a description, or "".
func CampaignMarkerOf(description string) string {
	if m := campaignMarker.FindStringSubmatch(description); len(m) == 2 {
		return m[1]
	}
	return ""
}

// CampaignName is the GitHub name for a Vulnetix campaign, within the limit.
func CampaignName(name string) string {
	n := "[Vulnetix] " + strings.TrimSpace(name)
	if r := []rune(n); len(r) > CampaignNameMax {
		n = string(r[:CampaignNameMax])
	}
	return n
}

// CampaignEnd formats a campaign end time the way the API takes it.
func CampaignEnd(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// Alert is a code scanning alert, reduced to what mapping needs.
type Alert struct {
	Number int    `json:"number"`
	State  string `json:"state"`
	Rule   struct {
		ID   string   `json:"id"`
		Tags []string `json:"tags"`
	} `json:"rule"`
	MostRecentInstance struct {
		Category string `json:"category"`
		Message  struct {
			Text string `json:"text"`
		} `json:"message"`
		Location struct {
			Path string `json:"path"`
		} `json:"location"`
	} `json:"most_recent_instance"`
}

// ListOpenAlerts returns the repository's open code scanning alerts.
func (c *Client) ListOpenAlerts(ctx context.Context, repo string) ([]Alert, error) {
	var out []Alert
	err := c.GetAll(ctx, fmt.Sprintf("/repos/%s/code-scanning/alerts?state=open&per_page=100", repo), &out)
	return out, err
}

// RepositoryID returns the numeric id of owner/name.
func (c *Client) RepositoryID(ctx context.Context, repo string) (int, error) {
	var out struct {
		ID int `json:"id"`
	}
	if _, err := c.Do(ctx, http.MethodGet, "/repos/"+repo, nil, &out); err != nil {
		return 0, err
	}
	return out.ID, nil
}
