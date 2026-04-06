package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// GitHubProvider fetches Dependabot alerts using the gh CLI.
type GitHubProvider struct{}

// NewGitHubProvider creates a new GitHub provider.
func NewGitHubProvider() Provider {
	return &GitHubProvider{}
}

// ghDependabotAlert matches the GitHub Dependabot Alerts API response.
type ghDependabotAlert struct {
	Number     int    `json:"number"`
	State      string `json:"state"`
	HTMLURL    string `json:"html_url"`
	Dependency struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		ManifestPath string `json:"manifest_path"`
		Scope        string `json:"scope"`
	} `json:"dependency"`
	SecurityAdvisory struct {
		CVEID       string `json:"cve_id"`
		Severity    string `json:"severity"`
		Summary     string `json:"summary"`
		WithdrawnAt string `json:"withdrawn_at"`
	} `json:"security_advisory"`
	SecurityVulnerabilities []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		FirstPatchedVersion *struct {
			Identifier string `json:"identifier"`
		} `json:"first_patched_version"`
		VulnerableVersionRange string `json:"vulnerable_version_range"`
		Severity               string `json:"severity"`
	} `json:"security_vulnerabilities"`
}

// GHStatus holds the results of GitHub CLI health checks.
type GHStatus struct {
	BinaryFound   bool   `json:"binary_found"`
	BinaryPath    string `json:"binary_path,omitempty"`
	Authenticated bool   `json:"authenticated"`
	User          string `json:"user,omitempty"`
	Host          string `json:"host,omitempty"`
	TokenSource   string `json:"token_source,omitempty"`
	TokenScopes   string `json:"token_scopes,omitempty"`
	RepoDetected  bool   `json:"repo_detected"`
	Repo          string `json:"repo,omitempty"`
	BinaryError   string `json:"binary_error,omitempty"`
	AuthError     string `json:"auth_error,omitempty"`
}

// CheckGH verifies the gh CLI binary is available.
func CheckGH() GHStatus {
	s := GHStatus{}
	path, err := exec.LookPath("gh")
	if err != nil {
		s.BinaryFound = false
		s.BinaryError = "gh CLI not found — install it from https://cli.github.com/"
		return s
	}
	s.BinaryFound = true
	s.BinaryPath = path
	return s
}

// CheckGHAuth verifies the gh CLI is available and the user is authenticated.
func CheckGHAuth() GHStatus {
	s := CheckGH()
	if !s.BinaryFound {
		return s
	}

	// Get auth status details
	stdout, stderr, err := runGH("auth", "status")
	if err != nil {
		s.Authenticated = false
		s.AuthError = strings.TrimSpace(stderr)
		if s.AuthError == "" {
			s.AuthError = err.Error()
		}
		return s
	}

	s.Authenticated = true

	// Parse user from stdout: "Logged in to github.com as username (...)"
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Logged in to ") {
			// "Logged in to github.com as user (method)"
			parts := strings.SplitN(strings.TrimPrefix(line, "Logged in to "), " as ", 2)
			if len(parts) == 2 {
				s.Host = parts[0]
				userPart := parts[1]
				if idx := strings.Index(userPart, " ("); idx > 0 {
					s.User = userPart[:idx]
				} else {
					s.User = userPart
				}
			}
			break
		}
	}

	// Get token scopes
	scopes, _, _ := runGH("auth", "status", "--scopes")
	if scopes != "" {
		s.TokenScopes = strings.TrimSpace(scopes)
	}

	// Token source is in the output
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Token:") {
			s.TokenSource = strings.TrimSpace(strings.TrimPrefix(line, "Token:"))
		}
	}

	return s
}

// RequireGH returns an error if the gh CLI is not available.
func RequireGH() error {
	s := CheckGH()
	if !s.BinaryFound {
		return fmt.Errorf("%s", s.BinaryError)
	}
	return nil
}

// RequireGHAuth returns an error if the gh CLI is not available or not authenticated.
func RequireGHAuth() error {
	if err := RequireGH(); err != nil {
		return err
	}
	s := CheckGHAuth()
	if !s.Authenticated {
		msg := "gh CLI is not authenticated"
		if s.AuthError != "" {
			msg += ": " + s.AuthError
		}
		return fmt.Errorf("%s — run 'gh auth login' to authenticate", msg)
	}
	return nil
}

// FetchAlerts retrieves Dependabot alerts from the given repository.
func (p *GitHubProvider) FetchAlerts(ctx context.Context, opts FetchOptions) ([]Alert, error) {
	if err := requireGH(); err != nil {
		return nil, err
	}

	if opts.Repo == "" {
		return nil, fmt.Errorf("no repository specified (use --repo flag or set GITHUB_REPOSITORY)")
	}

	// Determine which states to query.
	states := []string{"open"}
	if opts.IncludeDismissed {
		states = []string{"open", "dismissed", "fixed", "auto_dismissed"}
	}

	// Deduplicate alerts that may appear across multiple state queries.
	seen := map[int]bool{}
	var allAlerts []ghDependabotAlert

	for _, state := range states {
		alerts, err := p.fetchAlertsByState(ctx, opts.Repo, state)
		if err != nil {
			return nil, err
		}
		for _, a := range alerts {
			if !seen[a.Number] {
				seen[a.Number] = true
				allAlerts = append(allAlerts, a)
			}
		}
	}

	return mapGHAlertsToAlerts(allAlerts), nil
}

// fetchAlertsByState retrieves alerts for a single state with manual pagination.
func (p *GitHubProvider) fetchAlertsByState(ctx context.Context, repo, state string) ([]ghDependabotAlert, error) {
	perPage := 100
	var alerts []ghDependabotAlert

	for page := 1; ; page++ {
		path := fmt.Sprintf("repos/%s/dependabot/alerts?state=%s&per_page=%d&page=%d", repo, state, perPage, page)
		stdout, _, err := runGHContext(ctx, "api", path)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch alerts (state=%s, page=%d): %w", state, page, err)
		}

		var pageAlerts []ghDependabotAlert
		if err := json.Unmarshal([]byte(stdout), &pageAlerts); err != nil {
			return nil, fmt.Errorf("failed to parse alerts JSON: %w", err)
		}

		alerts = append(alerts, pageAlerts...)

		if len(pageAlerts) < perPage {
			break
		}
	}

	return alerts, nil
}

// mapGHAlertsToAlerts converts GitHub API alerts to normalized Alert structs.
func mapGHAlertsToAlerts(ghAlerts []ghDependabotAlert) []Alert {
	alerts := make([]Alert, 0, len(ghAlerts))
	for _, ga := range ghAlerts {
		for _, sv := range ga.SecurityVulnerabilities {
			version := ""
			if sv.FirstPatchedVersion != nil {
				version = sv.FirstPatchedVersion.Identifier
			}

			alerts = append(alerts, Alert{
				Number:    fmt.Sprintf("%d", ga.Number),
				State:     ga.State,
				CVE:       ga.SecurityAdvisory.CVEID,
				Severity:  sv.Severity,
				Package:   sv.Package.Name,
				Version:   version,
				Ecosystem: sv.Package.Ecosystem,
				Manifest:  ga.Dependency.ManifestPath,
				URL:       ga.HTMLURL,
			})
		}
	}
	return alerts
}

// requireGH checks if the gh CLI is available.
func requireGH() error {
	_, err := exec.LookPath("gh")
	if err != nil {
		return fmt.Errorf("gh CLI not found — install it from https://cli.github.com/")
	}
	return nil
}

// runGH runs the gh CLI with the given arguments and returns stdout.
func runGH(args ...string) (stdout string, stderr string, err error) {
	cmd := exec.Command("gh", args...)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return strings.TrimSpace(outBuf.String()), strings.TrimSpace(errBuf.String()), err
}

// runGHContext is like runGH but with a context for cancellation.
func runGHContext(ctx context.Context, args ...string) (stdout string, stderr string, err error) {
	cmd := exec.CommandContext(ctx, "gh", args...)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return strings.TrimSpace(outBuf.String()), strings.TrimSpace(errBuf.String()), err
}

// DetectRepo attempts to detect the current repository from various sources.
func DetectRepo() string {
	// 1. GITHUB_REPOSITORY env var (available in GitHub Actions)
	if repo := detectEnvRepo(); repo != "" {
		return repo
	}

	// 2. Try `gh repo view`
	if repo := detectGHRepo(); repo != "" {
		return repo
	}

	// 3. Try git remote
	if repo := detectGitRemote(); repo != "" {
		return repo
	}

	return ""
}

func detectEnvRepo() string {
	return strings.TrimSpace(os.Getenv("GITHUB_REPOSITORY"))
}

func detectGHRepo() string {
	stdout, _, err := runGH("repo", "view", "--json", "owner,name", "--jq", ".owner.login + \"/\" + .name")
	if err != nil {
		return ""
	}
	return stdout
}

func detectGitRemote() string {
	cmd := exec.Command("git", "remote", "get-url", "origin")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return parseGitRemoteURL(strings.TrimSpace(string(out)))
}

func parseGitRemoteURL(raw string) string {
	// git@github.com:owner/repo.git → owner/repo
	// https://github.com/owner/repo.git → owner/repo
	raw = strings.TrimSuffix(raw, ".git")
	if strings.HasPrefix(raw, "git@github.com:") {
		return strings.TrimPrefix(raw, "git@github.com:")
	}
	if strings.HasPrefix(raw, "https://github.com/") {
		return strings.TrimPrefix(raw, "https://github.com/")
	}
	return ""
}
