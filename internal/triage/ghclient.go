package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// GitHubClient is a native Go HTTP client for the GitHub REST API.
// It resolves a token once (from env or gh CLI) and reuses it for all requests.
type GitHubClient struct {
	token       string
	tokenSource string // "env:GITHUB_TOKEN", "env:GH_TOKEN", "gh-cli"
	httpClient  *http.Client
	baseURL     string
}

// NewGitHubClient creates a GitHubClient by resolving a token from environment
// variables or the gh CLI (single exec call).
func NewGitHubClient() (*GitHubClient, error) {
	c := &GitHubClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    "https://api.github.com",
	}

	// 1. GITHUB_TOKEN env var
	if t := os.Getenv("GITHUB_TOKEN"); t != "" {
		c.token = t
		c.tokenSource = "env:GITHUB_TOKEN"
		return c, nil
	}

	// 2. GH_TOKEN env var (gh CLI convention)
	if t := os.Getenv("GH_TOKEN"); t != "" {
		c.token = t
		c.tokenSource = "env:GH_TOKEN"
		return c, nil
	}

	// 3. Single exec call: gh auth token
	out, err := exec.Command("gh", "auth", "token").Output()
	if err == nil {
		tok := strings.TrimSpace(string(out))
		if tok != "" {
			c.token = tok
			c.tokenSource = "gh-cli"
			return c, nil
		}
	}

	return nil, fmt.Errorf("no GitHub token found — set GITHUB_TOKEN env var or run 'gh auth login'")
}

// TokenSource returns how the token was resolved (for status display).
func (c *GitHubClient) TokenSource() string {
	return c.tokenSource
}

// Do performs an authenticated GitHub API request and decodes the JSON response.
func (c *GitHubClient) Do(ctx context.Context, method, path string, result any) (*http.Response, error) {
	url := c.resolveURL(path)

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return resp, fmt.Errorf("GitHub API rate limit exceeded (resets at %s)", resp.Header.Get("X-RateLimit-Reset"))
		}
	}

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return resp, fmt.Errorf("GitHub API %s %s returned %d: %s", method, path, resp.StatusCode, string(body))
	}

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return resp, fmt.Errorf("failed to decode response from %s: %w", path, err)
		}
	}

	return resp, nil
}

// GetPaginated fetches all pages of a paginated GitHub API endpoint,
// following Link rel="next" headers. Returns concatenated JSON array items.
func (c *GitHubClient) GetPaginated(ctx context.Context, path string) ([]json.RawMessage, error) {
	var all []json.RawMessage
	url := c.resolveURL(path)

	for url != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") == "0" {
			resp.Body.Close()
			return nil, fmt.Errorf("GitHub API rate limit exceeded (resets at %s)", resp.Header.Get("X-RateLimit-Reset"))
		}

		if resp.StatusCode >= 400 {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("GitHub API GET %s returned %d: %s", path, resp.StatusCode, string(body))
		}

		var page []json.RawMessage
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode paginated response: %w", err)
		}
		resp.Body.Close()

		all = append(all, page...)
		url = parseLinkNext(resp.Header.Get("Link"))
	}

	return all, nil
}

// CheckAuth validates the token by calling GET /user and returns the login name.
func (c *GitHubClient) CheckAuth(ctx context.Context) (string, error) {
	var user struct {
		Login string `json:"login"`
	}
	_, err := c.Do(ctx, http.MethodGet, "/user", &user)
	if err != nil {
		return "", fmt.Errorf("authentication failed: %w", err)
	}
	return user.Login, nil
}

// resolveURL turns a path like "/repos/o/r/..." into a full URL,
// or returns the string as-is if it's already absolute.
func (c *GitHubClient) resolveURL(path string) string {
	if strings.HasPrefix(path, "https://") || strings.HasPrefix(path, "http://") {
		return path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return c.baseURL + path
}

// linkNextRe matches <URL>; rel="next" in a Link header.
var linkNextRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// parseLinkNext extracts the "next" URL from a GitHub Link header.
// Returns "" if there is no next page.
func parseLinkNext(header string) string {
	m := linkNextRe.FindStringSubmatch(header)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}
