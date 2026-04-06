package triage

import (
	"context"
	"encoding/json"
	"fmt"
)

// ghCodeQLAlert matches the GitHub Code Scanning Alerts API response.
type ghCodeQLAlert struct {
	Number  int    `json:"number"`
	State   string `json:"state"`
	HTMLURL string `json:"html_url"`
	Rule    struct {
		ID               string   `json:"id"`
		Severity         string   `json:"severity"`
		SecuritySeverity string   `json:"security_severity_level"`
		Description      string   `json:"description"`
		Tags             []string `json:"tags"`
	} `json:"rule"`
	MostRecentInstance struct {
		Ref      string `json:"ref"`
		Location struct {
			Path      string `json:"path"`
			StartLine int    `json:"start_line"`
		} `json:"location"`
	} `json:"most_recent_instance"`
	DismissedReason string `json:"dismissed_reason"`
}

// fetchCodeQLAlerts retrieves Code Scanning (CodeQL) alerts for a repository.
func fetchCodeQLAlerts(ctx context.Context, client *GitHubClient, repo string, opts FetchOptions) ([]Alert, error) {
	states := []string{"open"}
	if opts.IncludeDismissed {
		states = []string{"open", "dismissed", "fixed"}
	}

	seen := map[int]bool{}
	var all []ghCodeQLAlert

	for _, state := range states {
		path := fmt.Sprintf("/repos/%s/code-scanning/alerts?state=%s&per_page=100", repo, state)
		pages, err := client.GetPaginated(ctx, path)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch code-scanning alerts (state=%s): %w", state, err)
		}
		for _, raw := range pages {
			var a ghCodeQLAlert
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, fmt.Errorf("failed to parse code-scanning alert: %w", err)
			}
			if !seen[a.Number] {
				seen[a.Number] = true
				all = append(all, a)
			}
		}
	}

	return mapCodeQLAlerts(all), nil
}

// mapCodeQLAlerts converts GitHub Code Scanning alerts to normalized Alerts.
func mapCodeQLAlerts(alerts []ghCodeQLAlert) []Alert {
	out := make([]Alert, 0, len(alerts))
	for _, a := range alerts {
		sev := a.Rule.SecuritySeverity
		if sev == "" {
			sev = a.Rule.Severity
		}

		// Extract CWE from tags (e.g. "cwe-79")
		var cwe string
		for _, tag := range a.Rule.Tags {
			if len(tag) > 4 && tag[:4] == "cwe-" {
				cwe = tag
				break
			}
		}

		out = append(out, Alert{
			Number:          fmt.Sprintf("%d", a.Number),
			State:           a.State,
			CVE:             a.Rule.ID,
			Severity:        sev,
			Package:         a.MostRecentInstance.Location.Path,
			Ecosystem:       "codeql",
			URL:             a.HTMLURL,
			DismissalReason: a.DismissedReason,
			CWE:             cwe,
		})
	}
	return out
}
