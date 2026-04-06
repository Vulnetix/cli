package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// GHStatus holds the results of GitHub health checks.
type GHStatus struct {
	BinaryFound   bool   `json:"binary_found"`
	BinaryPath    string `json:"binary_path,omitempty"`
	Authenticated bool   `json:"authenticated"`
	User          string `json:"user,omitempty"`
	Host          string `json:"host,omitempty"`
	TokenSource   string `json:"token_source,omitempty"`
	RepoDetected  bool   `json:"repo_detected"`
	Repo          string `json:"repo,omitempty"`
	BinaryError   string `json:"binary_error,omitempty"`
	AuthError     string `json:"auth_error,omitempty"`
}

// CheckGHAuth verifies GitHub API access using the GitHubClient.
func CheckGHAuth(client *GitHubClient) GHStatus {
	s := GHStatus{
		Host: "github.com",
	}

	// Check if gh binary exists (optional info for status display)
	path, err := exec.LookPath("gh")
	if err == nil {
		s.BinaryFound = true
		s.BinaryPath = path
	}

	s.TokenSource = client.TokenSource()

	login, err := client.CheckAuth(context.Background())
	if err != nil {
		s.Authenticated = false
		s.AuthError = err.Error()
		return s
	}

	s.Authenticated = true
	s.User = login
	return s
}

// DetectRepo attempts to detect the current repository from various sources.
func DetectRepo() string {
	// 1. GITHUB_REPOSITORY env var (available in GitHub Actions)
	if repo := strings.TrimSpace(os.Getenv("GITHUB_REPOSITORY")); repo != "" {
		return repo
	}

	// 2. git remote origin
	if repo := detectGitRemote(); repo != "" {
		return repo
	}

	return ""
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
	raw = strings.TrimSuffix(raw, ".git")
	if strings.HasPrefix(raw, "git@github.com:") {
		return strings.TrimPrefix(raw, "git@github.com:")
	}
	if strings.HasPrefix(raw, "https://github.com/") {
		return strings.TrimPrefix(raw, "https://github.com/")
	}
	return ""
}

// ---------------------------------------------------------------------------
// Dependabot alerts (native HTTP)
// ---------------------------------------------------------------------------

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

// fetchDependabotAlerts retrieves Dependabot alerts for a repository using native HTTP.
func fetchDependabotAlerts(ctx context.Context, client *GitHubClient, repo string, opts FetchOptions) ([]Alert, error) {
	states := []string{"open"}
	if opts.IncludeDismissed {
		states = []string{"open", "dismissed", "fixed", "auto_dismissed"}
	}

	seen := map[int]bool{}
	var all []ghDependabotAlert

	for _, state := range states {
		path := fmt.Sprintf("/repos/%s/dependabot/alerts?state=%s&per_page=100", repo, state)
		pages, err := client.GetPaginated(ctx, path)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch dependabot alerts (state=%s): %w", state, err)
		}
		for _, raw := range pages {
			var a ghDependabotAlert
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, fmt.Errorf("failed to parse dependabot alert: %w", err)
			}
			if !seen[a.Number] {
				seen[a.Number] = true
				all = append(all, a)
			}
		}
	}

	return mapGHAlertsToAlerts(all), nil
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
