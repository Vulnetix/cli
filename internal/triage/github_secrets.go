package triage

import (
	"context"
	"encoding/json"
	"fmt"
)

// ghSecretAlert matches the GitHub Secret Scanning Alerts API response.
type ghSecretAlert struct {
	Number          int    `json:"number"`
	State           string `json:"state"`
	HTMLURL         string `json:"html_url"`
	SecretType      string `json:"secret_type"`
	SecretTypeLabel string `json:"secret_type_display_name"`
	Resolution      string `json:"resolution"`
	LocationsURL    string `json:"locations_url"`
}

// fetchSecretAlerts retrieves Secret Scanning alerts for a repository.
func fetchSecretAlerts(ctx context.Context, client *GitHubClient, repo string, opts FetchOptions) ([]Alert, error) {
	states := []string{"open"}
	if opts.IncludeDismissed {
		states = []string{"open", "resolved"}
	}

	seen := map[int]bool{}
	var all []ghSecretAlert

	for _, state := range states {
		path := fmt.Sprintf("/repos/%s/secret-scanning/alerts?state=%s&per_page=100", repo, state)
		pages, err := client.GetPaginated(ctx, path)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch secret-scanning alerts (state=%s): %w", state, err)
		}
		for _, raw := range pages {
			var a ghSecretAlert
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, fmt.Errorf("failed to parse secret-scanning alert: %w", err)
			}
			if !seen[a.Number] {
				seen[a.Number] = true
				all = append(all, a)
			}
		}
	}

	return mapSecretAlerts(all), nil
}

// mapSecretAlerts converts GitHub Secret Scanning alerts to normalized Alerts.
func mapSecretAlerts(alerts []ghSecretAlert) []Alert {
	out := make([]Alert, 0, len(alerts))
	for _, a := range alerts {
		label := a.SecretTypeLabel
		if label == "" {
			label = a.SecretType
		}
		out = append(out, Alert{
			Number:          fmt.Sprintf("%d", a.Number),
			State:           a.State,
			RuleID:          a.SecretType,
			Description:     label,
			Severity:        "critical",
			Ecosystem:       "secrets",
			URL:             a.HTMLURL,
			DismissalReason: a.Resolution,
		})
	}
	return out
}
