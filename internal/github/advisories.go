package github

// Repository security advisories (drafts):
// GET/POST /repos/{owner}/{repo}/security-advisories and
// PATCH .../security-advisories/{ghsa_id}.
//
// Only drafts are ever created or edited. Nothing here publishes an advisory:
// publishing tells the world about a vulnerability, and that stays a decision
// a maintainer makes in GitHub. The token needs repository advisories write
// (a PAT or a GitHub App); the workflow GITHUB_TOKEN cannot do this.

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
)

// AdvisoryPackage names the affected package.
type AdvisoryPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name,omitempty"`
}

// AdvisoryVulnerability is one affected package.
type AdvisoryVulnerability struct {
	Package AdvisoryPackage `json:"package"`
}

// AdvisoryRequest is the create and update body. Severity and a CVSS vector
// are mutually exclusive in the API; only Severity is ever sent.
type AdvisoryRequest struct {
	Summary         string                  `json:"summary"`
	Description     string                  `json:"description"`
	Vulnerabilities []AdvisoryVulnerability `json:"vulnerabilities,omitempty"`
	CWEIDs          []string                `json:"cwe_ids,omitempty"`
	Severity        string                  `json:"severity,omitempty"`
}

// RepositoryAdvisory is an advisory as listed.
type RepositoryAdvisory struct {
	GHSAID      string `json:"ghsa_id"`
	Summary     string `json:"summary"`
	Description string `json:"description"`
	State       string `json:"state"`
	HTMLURL     string `json:"html_url"`
}

// ListAdvisories returns every repository advisory, all states.
func (c *Client) ListAdvisories(ctx context.Context, repo string) ([]RepositoryAdvisory, error) {
	var out []RepositoryAdvisory
	err := c.GetAll(ctx, fmt.Sprintf("/repos/%s/security-advisories?per_page=100", repo), &out)
	return out, err
}

// CreateAdvisory creates a draft advisory.
func (c *Client) CreateAdvisory(ctx context.Context, repo string, req AdvisoryRequest) (*RepositoryAdvisory, error) {
	var out RepositoryAdvisory
	if _, err := c.Do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/security-advisories", repo), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateAdvisory edits a draft advisory. It never sends a state, so it cannot
// publish one.
func (c *Client) UpdateAdvisory(ctx context.Context, repo, ghsaID string, req AdvisoryRequest) (*RepositoryAdvisory, error) {
	var out RepositoryAdvisory
	if _, err := c.Do(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/security-advisories/%s", repo, ghsaID), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

var advisoryMarker = regexp.MustCompile(`<!-- vulnetix-advisory:([0-9a-f]+) -->`)

// AdvisoryMarker is the line that ties an advisory to the finding group it was
// made from.
func AdvisoryMarker(hash string) string {
	return "<!-- vulnetix-advisory:" + hash + " -->"
}

// MarkerOf returns the marker hash in an advisory's description, or "".
func MarkerOf(description string) string {
	if m := advisoryMarker.FindStringSubmatch(description); len(m) == 2 {
		return m[1]
	}
	return ""
}
