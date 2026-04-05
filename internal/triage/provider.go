// Package triage provides a provider abstraction for fetching vulnerability
// alerts from external sources (GitHub Dependabot, Snyk, etc.) and
// enriching them with VDB remediation data.
package triage

import (
	"context"
	"fmt"
)

// Alert represents a normalized vulnerability alert from any provider.
type Alert struct {
	// Number or ID of the alert in the provider system
	Number string
	// State: "open", "dismissed", "fixed"
	State string
	// CVE identifier
	CVE string
	// Severity: "critical", "high", "medium", "low"
	Severity string
	// Package name (e.g. "lodash", "express")
	Package string
	// Current vulnerable version
	Version string
	// Ecosystem as reported by the provider (needs mapping to VDB format)
	Ecosystem string
	// Path to the manifest file containing the vulnerable dependency
	Manifest string
	// URL to the alert in the provider's UI
	URL string
}

// FetchOptions controls which alerts are retrieved.
type FetchOptions struct {
	IncludeDismissed bool
	Repo             string
}

// Provider is the interface that all triage providers must implement.
type Provider interface {
	// FetchAlerts retrieves vulnerability alerts from the provider.
	FetchAlerts(ctx context.Context, opts FetchOptions) ([]Alert, error)
}

// Providers is the registry of available providers.
var Providers = map[string]func() Provider{
	"github": NewGitHubProvider,
}

// GetProvider returns the provider for the given name, or an error if unknown.
func GetProvider(name string) (Provider, error) {
	fn, ok := Providers[name]
	if !ok {
		return nil, fmt.Errorf("unknown provider %q (supported: github)", name)
	}
	return fn(), nil
}

// EnrichedAlert holds a provider alert with VDB enrichment data.
type EnrichedAlert struct {
	Alert         Alert                  `json:"alert"`
	Remediation   *map[string]any        `json:"remediation,omitempty"`
	Fixes         *FixesMerged           `json:"fixes,omitempty"`
	Error         string                 `json:"error,omitempty"`
}

// FixesMerged holds fix data from multiple sources.
type FixesMerged struct {
	Registry      map[string]any
	Distributions map[string]any
	Source        map[string]any
}

// HasFix returns true if any fix source has fixes available.
func (f *FixesMerged) HasFix() bool {
	if f == nil {
		return false
	}
	if f.Registry != nil {
		if fixes, ok := f.Registry["fixes"].([]any); ok && len(fixes) > 0 {
			return true
		}
	}
	if f.Distributions != nil {
		if patches, ok := f.Distributions["patches"].([]any); ok && len(patches) > 0 {
			return true
		}
	}
	if f.Source != nil {
		if fixes, ok := f.Source["fixes"].([]any); ok && len(fixes) > 0 {
			return true
		}
	}
	return false
}
