package vdb

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	// StaticEnumTTL is the cache TTL for slowly-changing enumeration endpoints.
	StaticEnumTTL = 1 * time.Hour
	// PaginatedEnumTTL is the cache TTL for paginated list endpoints.
	PaginatedEnumTTL = 5 * time.Minute
)

// CVEInfo represents vulnerability information for a CVE
type CVEInfo struct {
	Data interface{} // Store full response for display (array or object)
}

// Ecosystem represents a single ecosystem entry
type Ecosystem struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// EcosystemsResponse represents the ecosystems list response
type EcosystemsResponse struct {
	Timestamp  int64       `json:"timestamp"`
	Ecosystems []Ecosystem `json:"ecosystems"`
}

// VersionSource represents a data source entry for a product version
type VersionSource struct {
	SourceTable string                 `json:"sourceTable"`
	SourceID    string                 `json:"sourceId"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// VersionRecord represents a single version entry with ecosystem and sources
type VersionRecord struct {
	Version   string          `json:"version"`
	Ecosystem string          `json:"ecosystem"`
	Sources   []VersionSource `json:"sources"`
	CVEIDs    []string        `json:"cveIds,omitempty"`
}

// ProductVersionsResponse represents product versions with pagination
type ProductVersionsResponse struct {
	PackageName string          `json:"packageName"`
	Timestamp   int64           `json:"timestamp"`
	Total       int             `json:"total"`
	Limit       int             `json:"limit"`
	Offset      int             `json:"offset"`
	HasMore     bool            `json:"hasMore"`
	Versions    []VersionRecord `json:"versions"`
}

// VulnerabilitiesResponse represents vulnerabilities for a package
type VulnerabilitiesResponse struct {
	PackageName     string          `json:"packageName"`
	Timestamp       int64           `json:"timestamp"`
	TotalCVEs       int             `json:"totalCVEs"`
	Total           int             `json:"total"`
	Limit           int             `json:"limit"`
	Offset          int             `json:"offset"`
	HasMore         bool            `json:"hasMore"`
	Versions        []VersionRecord `json:"versions"`
	Vulnerabilities []VersionRecord `json:"vulnerabilities"` // alternative key used by some API paths
	RawData         interface{}     `json:"-"`               // full parsed response for fallback display
}

// GCVEIssuancesResponse represents the paginated GCVE issuances response
type GCVEIssuancesResponse struct {
	Timestamp   int64                    `json:"timestamp"`
	Year        int                      `json:"year"`
	Month       int                      `json:"month"`
	Total       int                      `json:"total"`
	Limit       int                      `json:"limit"`
	Offset      int                      `json:"offset"`
	HasMore     bool                     `json:"hasMore"`
	Identifiers []GCVEIssuanceIdentifier `json:"identifiers"`
}

// GCVEIssuanceIdentifier represents a single GCVE issuance record
type GCVEIssuanceIdentifier struct {
	GcveID        string `json:"gcveId"`
	CveID         string `json:"cveId"`
	DatePublished int64  `json:"datePublished"`
}

// GetGCVEIssuances retrieves GCVE issuances for a given year/month with pagination
func (c *Client) GetGCVEIssuances(year, month, limit, offset int) (*GCVEIssuancesResponse, error) {
	path := fmt.Sprintf("/gcve/%d/%d", year, month)
	path += buildPaginationQuery(limit, offset)

	respBody, err := c.DoRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var resp GCVEIssuancesResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// GetCVE retrieves full vulnerability data for a specific CVE
func (c *Client) GetCVE(cveID string) (*CVEInfo, error) {
	path := fmt.Sprintf("/vuln/%s", cveID)

	respBody, err := c.DoRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var data interface{}
	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &CVEInfo{Data: data}, nil
}

// GetEcosystems retrieves the list of available ecosystems
func (c *Client) GetEcosystems() ([]Ecosystem, error) {
	path := "/ecosystems"

	respBody, err := c.DoRequestCached("GET", path, nil, StaticEnumTTL)
	if err != nil {
		return nil, err
	}

	var resp EcosystemsResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resp.Ecosystems, nil
}

// buildPaginationQuery constructs a query string for pagination parameters.
// It returns an empty string if neither limit nor offset is greater than zero.
func buildPaginationQuery(limit, offset int) string {
	if limit <= 0 && offset <= 0 {
		return ""
	}

	params := url.Values{}
	if limit > 0 {
		params.Add("limit", fmt.Sprintf("%d", limit))
	}
	if offset > 0 {
		params.Add("offset", fmt.Sprintf("%d", offset))
	}

	return "?" + params.Encode()
}

// GetProductVersions retrieves all versions for a product with pagination
func (c *Client) GetProductVersions(productName string, limit, offset int) (*ProductVersionsResponse, error) {
	path := fmt.Sprintf("/product/%s", url.PathEscape(productName))

	// Add pagination parameters
	path += buildPaginationQuery(limit, offset)

	respBody, err := c.DoRequestCached("GET", path, nil, PaginatedEnumTTL)
	if err != nil {
		return nil, err
	}

	var resp ProductVersionsResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// GetProductVersion retrieves information for a specific product version
func (c *Client) GetProductVersion(productName, version string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/product/%s/%s", url.PathEscape(productName), url.PathEscape(version))

	respBody, err := c.DoRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// GetPackageVulnerabilities retrieves vulnerabilities for a package
func (c *Client) GetPackageVulnerabilities(packageName string, limit, offset int) (*VulnerabilitiesResponse, error) {
	path := fmt.Sprintf("/%s/vulns", url.PathEscape(packageName))

	// Add pagination parameters
	path += buildPaginationQuery(limit, offset)

	respBody, err := c.DoRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var resp VulnerabilitiesResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	var raw interface{}
	_ = json.Unmarshal(respBody, &raw)
	resp.RawData = raw

	return &resp, nil
}

// GetHealth checks the API health endpoint (unauthenticated, root-level path).
func (c *Client) GetHealth() (map[string]interface{}, error) {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return map[string]interface{}{"status": "unreachable", "error": err.Error()}, nil
	}
	healthURL := fmt.Sprintf("%s://%s/health", u.Scheme, u.Host)

	resp, err := http.Get(healthURL) //nolint:noctx
	if err != nil {
		return map[string]interface{}{"status": "unreachable", "error": err.Error()}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return map[string]interface{}{"http_status_code": resp.StatusCode}, nil
	}
	result["http_status_code"] = resp.StatusCode
	return result, nil
}

// GetOpenAPISpec retrieves the OpenAPI specification
func (c *Client) GetOpenAPISpec() (map[string]interface{}, error) {
	path := "/spec"

	respBody, err := c.DoRequestCached("GET", path, nil, StaticEnumTTL)
	if err != nil {
		return nil, err
	}

	var spec map[string]interface{}
	if err := json.Unmarshal(respBody, &spec); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return spec, nil
}

// GetExploits retrieves exploit intelligence for a specific CVE identifier
func (c *Client) GetExploits(identifier string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/exploits/%s", url.PathEscape(identifier))

	respBody, err := c.DoRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// GetCVETimeline retrieves the vulnerability timeline from the v1 API.
func (c *Client) GetCVETimeline(identifier string, params TimelineParams) (map[string]interface{}, error) {
	q := url.Values{}
	if params.Include != "" {
		q.Set("include", params.Include)
	}
	if params.Exclude != "" {
		q.Set("exclude", params.Exclude)
	}
	if params.Dates != "" {
		q.Set("dates", params.Dates)
	}
	if params.ScoresLimit > 0 {
		q.Set("scores_limit", fmt.Sprintf("%d", params.ScoresLimit))
	}
	path := fmt.Sprintf("/vuln/%s/timeline", url.PathEscape(identifier))
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}

	respBody, err := c.DoRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// GetCVEFixes retrieves fix data for a specific CVE identifier
func (c *Client) GetCVEFixes(identifier string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/vuln/%s/fixes", url.PathEscape(identifier))

	respBody, err := c.DoRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// GetTrafficFilters retrieves IDS/IPS traffic filter rules (Snort) for a vulnerability.
func (c *Client) GetTrafficFilters(identifier string, limit, offset int) (map[string]interface{}, error) {
	path := fmt.Sprintf("/vuln/%s/snort-rules?limit=%d&offset=%d", url.PathEscape(identifier), limit, offset)

	respBody, err := c.DoRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// GetPackageVersions retrieves all known versions for a package across ecosystems
func (c *Client) GetPackageVersions(packageName string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/%s/versions", url.PathEscape(packageName))

	respBody, err := c.DoRequestCached("GET", path, nil, PaginatedEnumTTL)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// IdentifiersMonthResponse represents the paginated CVE identifiers response by month
type IdentifiersMonthResponse struct {
	Timestamp   int64    `json:"timestamp"`
	Year        int      `json:"year"`
	Month       int      `json:"month"`
	Total       int      `json:"total"`
	Limit       int      `json:"limit"`
	Offset      int      `json:"offset"`
	HasMore     bool     `json:"hasMore"`
	Identifiers []string `json:"identifiers"`
}

// IdentifiersSearchResponse represents the paginated CVE identifiers search response
type IdentifiersSearchResponse struct {
	Timestamp   int64    `json:"timestamp"`
	Prefix      string   `json:"prefix"`
	Total       int      `json:"total"`
	Limit       int      `json:"limit"`
	Offset      int      `json:"offset"`
	HasMore     bool     `json:"hasMore"`
	Identifiers []string `json:"identifiers"`
}

// GetIdentifiersByMonth retrieves CVE identifiers published in a given year/month
func (c *Client) GetIdentifiersByMonth(year, month, limit, offset int) (*IdentifiersMonthResponse, error) {
	path := fmt.Sprintf("/identifiers/%d/%d", year, month)
	path += buildPaginationQuery(limit, offset)

	respBody, err := c.DoRequestCached("GET", path, nil, PaginatedEnumTTL)
	if err != nil {
		return nil, err
	}

	var resp IdentifiersMonthResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// SearchIdentifiers retrieves CVE identifiers matching a prefix
func (c *Client) SearchIdentifiers(prefix string, limit, offset int) (*IdentifiersSearchResponse, error) {
	params := url.Values{}
	params.Set("prefix", prefix)
	if limit > 0 {
		params.Set("limit", fmt.Sprintf("%d", limit))
	}
	if offset > 0 {
		params.Set("offset", fmt.Sprintf("%d", offset))
	}
	path := "/identifiers?" + params.Encode()

	respBody, err := c.DoRequestCached("GET", path, nil, PaginatedEnumTTL)
	if err != nil {
		return nil, err
	}

	var resp IdentifiersSearchResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &resp, nil
}

// GetCVEsByDateRange retrieves paginated CVEs by date range
func (c *Client) GetCVEsByDateRange(start, end string) (map[string]interface{}, error) {
	params := url.Values{}
	params.Set("start", start)
	params.Set("end", end)
	path := "/gcve?" + params.Encode()

	respBody, err := c.DoRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// GetSources retrieves the list of vulnerability data sources
func (c *Client) GetSources() (map[string]interface{}, error) {
	respBody, err := c.DoRequestCached("GET", "/sources", nil, StaticEnumTTL)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// GetMetricTypes retrieves the list of vulnerability metric/scoring types
func (c *Client) GetMetricTypes() (map[string]interface{}, error) {
	respBody, err := c.DoRequestCached("GET", "/metric-types", nil, StaticEnumTTL)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// GetExploitSources retrieves the list of exploit intelligence sources
func (c *Client) GetExploitSources() (map[string]interface{}, error) {
	respBody, err := c.DoRequestCached("GET", "/exploit-sources", nil, StaticEnumTTL)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// GetExploitTypes retrieves the list of exploit type classifications
func (c *Client) GetExploitTypes() (map[string]interface{}, error) {
	respBody, err := c.DoRequestCached("GET", "/exploit-types", nil, StaticEnumTTL)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// GetFixDistributions retrieves the list of supported Linux distributions for fix advisories
func (c *Client) GetFixDistributions() (map[string]interface{}, error) {
	respBody, err := c.DoRequestCached("GET", "/fix-distributions", nil, StaticEnumTTL)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// GetSummary retrieves global all-time database statistics.
func (c *Client) GetSummary() (map[string]interface{}, error) {
	respBody, err := c.DoRequestCached("GET", "/summary", nil, StaticEnumTTL)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// SearchExploits searches for exploits across CVEs with pagination and filters
func (c *Client) SearchExploits(params ExploitSearchParams) (map[string]interface{}, error) {
	q := url.Values{}
	if params.Limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", params.Limit))
	}
	if params.Offset > 0 {
		q.Set("offset", fmt.Sprintf("%d", params.Offset))
	}
	if params.Ecosystem != "" {
		q.Set("ecosystem", params.Ecosystem)
	}
	if params.Source != "" {
		q.Set("source", params.Source)
	}
	if params.Severity != "" {
		q.Set("severity", params.Severity)
	}
	if params.InKev != "" {
		q.Set("inKev", params.InKev)
	}
	if params.MinEpss != "" {
		q.Set("minEpss", params.MinEpss)
	}
	if params.Query != "" {
		q.Set("q", params.Query)
	}
	if params.Sort != "" {
		q.Set("sort", params.Sort)
	}

	path := "/exploits"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}

	respBody, err := c.DoRequestCached("GET", path, nil, PaginatedEnumTTL)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// ExploitSearchParams holds parameters for the exploit search endpoint
// TimelineParams holds filter parameters for the /vuln/{id}/timeline endpoint.
type TimelineParams struct {
	Include     string // comma-separated event types to include
	Exclude     string // comma-separated event types to exclude
	Dates       string // comma-separated CVE date fields: published,modified,reserved
	ScoresLimit int    // max score-change events (default 30, max 365)
}

type ExploitSearchParams struct {
	Limit     int
	Offset    int
	Ecosystem string
	Source    string
	Severity  string
	Sort      string
	Query     string
	InKev     string
	MinEpss   string
}

// SearchPackages performs a full-text search across packages
func (c *Client) SearchPackages(query, ecosystem string, limit, offset int) (map[string]interface{}, error) {
	q := url.Values{}
	q.Set("q", query)
	if ecosystem != "" {
		q.Set("ecosystem", ecosystem)
	}
	if limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", limit))
	}
	if offset > 0 {
		q.Set("offset", fmt.Sprintf("%d", offset))
	}

	path := "/packages/search?" + q.Encode()

	respBody, err := c.DoRequestCached("GET", path, nil, PaginatedEnumTTL)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// GetEcosystemPackage retrieves package information scoped to a specific ecosystem
func (c *Client) GetEcosystemPackage(ecosystem, pkg string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/%s/%s", url.PathEscape(ecosystem), url.PathEscape(pkg))

	respBody, err := c.DoRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// GetEcosystemPackageVersions retrieves version information for a package in a specific ecosystem
func (c *Client) GetEcosystemPackageVersions(ecosystem, pkg string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/%s/%s/versions", url.PathEscape(ecosystem), url.PathEscape(pkg))

	respBody, err := c.DoRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// GetEcosystemGroupPackage retrieves Maven-style group/artifact information in a specific ecosystem
func (c *Client) GetEcosystemGroupPackage(ecosystem, group, artifact string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/%s/%s/%s",
		url.PathEscape(ecosystem),
		url.PathEscape(group),
		url.PathEscape(artifact),
	)

	respBody, err := c.DoRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// GetProductVersionEcosystem retrieves product version information scoped to a specific ecosystem
func (c *Client) GetProductVersionEcosystem(productName, version, ecosystem string) (map[string]interface{}, error) {
	path := fmt.Sprintf("/product/%s/%s/%s",
		url.PathEscape(productName),
		url.PathEscape(version),
		url.PathEscape(ecosystem),
	)

	respBody, err := c.DoRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}
