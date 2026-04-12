package depsdev

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	BaseURL    = "https://api.deps.dev/v3"
	Timeout    = 10 * time.Second
	DefaultMax = 5
)

// Client is a deps.dev API v3 client with caching and concurrency control.
type Client struct {
	httpClient  *http.Client
	cache       sync.Map // endpoint URL → cached response bytes
	maxConc     int
}

// NewClient creates a new deps.dev client.
func NewClient(maxConcurrency int) *Client {
	if maxConcurrency <= 0 {
		maxConcurrency = DefaultMax
	}
	return &Client{
		httpClient: &http.Client{Timeout: Timeout},
		maxConc:    maxConcurrency,
	}
}

// MaxConcurrency returns the configured concurrency limit.
func (c *Client) MaxConcurrency() int {
	return c.maxConc
}

// get fetches a URL, using the cache if available.
func (c *Client) get(rawURL string) ([]byte, error) {
	if cached, ok := c.cache.Load(rawURL); ok {
		return cached.([]byte), nil
	}

	resp, err := c.httpClient.Get(rawURL)
	if err != nil {
		return nil, fmt.Errorf("deps.dev request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("deps.dev returned status %d for %s", resp.StatusCode, rawURL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("deps.dev read body failed: %w", err)
	}

	c.cache.Store(rawURL, body)
	return body, nil
}

// EcosystemToSystem maps internal ecosystem names to deps.dev system names.
// Returns "" for unsupported ecosystems.
func EcosystemToSystem(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "golang", "go":
		return "GO"
	case "npm":
		return "NPM"
	case "pypi":
		return "PYPI"
	case "cargo":
		return "CARGO"
	case "maven":
		return "MAVEN"
	case "nuget":
		return "NUGET"
	default:
		return ""
	}
}

// FetchVersion calls GET /v3/systems/{sys}/packages/{name}/versions/{ver}.
func (c *Client) FetchVersion(system, name, version string) (*VersionResponse, error) {
	u := fmt.Sprintf("%s/systems/%s/packages/%s/versions/%s",
		BaseURL,
		url.PathEscape(system),
		url.PathEscape(name),
		url.PathEscape(version))

	body, err := c.get(u)
	if err != nil {
		return nil, err
	}

	var resp VersionResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("deps.dev parse version response: %w", err)
	}
	return &resp, nil
}

// FetchPackage calls GET /v3/systems/{sys}/packages/{name}.
func (c *Client) FetchPackage(system, name string) (*PackageResponse, error) {
	u := fmt.Sprintf("%s/systems/%s/packages/%s",
		BaseURL,
		url.PathEscape(system),
		url.PathEscape(name))

	body, err := c.get(u)
	if err != nil {
		return nil, err
	}

	var resp PackageResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("deps.dev parse package response: %w", err)
	}
	return &resp, nil
}

// FetchAdvisory calls GET /v3/advisories/{key}.
func (c *Client) FetchAdvisory(advisoryID string) (*AdvisoryResponse, error) {
	u := fmt.Sprintf("%s/advisories/%s",
		BaseURL,
		url.PathEscape(advisoryID))

	body, err := c.get(u)
	if err != nil {
		return nil, err
	}

	var resp AdvisoryResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("deps.dev parse advisory response: %w", err)
	}
	return &resp, nil
}

// FetchProject calls GET /v3/projects/{key}.
func (c *Client) FetchProject(projectKey string) (*ProjectResponse, error) {
	u := fmt.Sprintf("%s/projects/%s",
		BaseURL,
		url.PathEscape(projectKey))

	body, err := c.get(u)
	if err != nil {
		return nil, err
	}

	var resp ProjectResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("deps.dev parse project response: %w", err)
	}
	return &resp, nil
}
