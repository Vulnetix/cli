package triage

import (
	"context"
	"fmt"
)

// GitHubMultiProvider fetches alerts from one or more GitHub security tools
// (Dependabot, CodeQL, Secret Scanning) using native HTTP calls.
type GitHubMultiProvider struct {
	Client *GitHubClient
	Kinds  []string // subset of "dependabot", "codeql", "secrets"
}

// NewGitHubMultiProvider creates a multi-provider. Call NewGitHubClient first.
func NewGitHubMultiProvider(client *GitHubClient, kinds []string) *GitHubMultiProvider {
	return &GitHubMultiProvider{Client: client, Kinds: kinds}
}

// FetchAlerts retrieves alerts from all configured GitHub security tools.
func (p *GitHubMultiProvider) FetchAlerts(ctx context.Context, opts FetchOptions) ([]Alert, error) {
	var all []Alert

	for _, kind := range p.Kinds {
		var alerts []Alert
		var err error

		switch kind {
		case "dependabot":
			alerts, err = fetchDependabotAlerts(ctx, p.Client, opts.Repo, opts)
		case "codeql":
			alerts, err = fetchCodeQLAlerts(ctx, p.Client, opts.Repo, opts)
		case "secrets":
			alerts, err = fetchSecretAlerts(ctx, p.Client, opts.Repo, opts)
		default:
			return nil, fmt.Errorf("unknown GitHub alert kind %q", kind)
		}

		if err != nil {
			return nil, fmt.Errorf("%s: %w", kind, err)
		}
		all = append(all, alerts...)
	}

	return all, nil
}
