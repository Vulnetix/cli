// Package triage provides a provider abstraction for fetching vulnerability
// alerts from external sources (GitHub Dependabot, Snyk, etc.) and
// enriching them with VDB remediation data.
package triage

import (
	"context"
	"fmt"

	"github.com/vulnetix/cli/internal/memory"
)

// Alert represents a normalized vulnerability alert from any provider.
type Alert struct {
	// Number or ID of the alert in the provider system
	Number string
	// State: "open", "dismissed", "fixed"
	State string
	// CVE identifier (empty for non-CVE alerts like CodeQL rules or secrets)
	CVE string
	// RuleID is the provider-specific rule identifier (e.g. CodeQL "js/bad-tag-filter")
	RuleID string
	// Description is a short summary of the finding
	Description string
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
	// Dismissal reason if state is "dismissed"
	DismissalReason string
	// CWE identifier if available
	CWE string
}

// Identifier returns the best display identifier for the alert:
// CVE if available, otherwise RuleID, otherwise the alert number.
func (a Alert) Identifier() string {
	if a.CVE != "" {
		return a.CVE
	}
	if a.RuleID != "" {
		return a.RuleID
	}
	return "#" + a.Number
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

// TriageProvider extends Provider with per-CVE triage capability.
type TriageProvider interface {
	Provider
	// TriageCVE fetches full vulnerability intelligence for a single CVE and
	// maps it to a TriageFinding (with CWSS, threat model, VEX status).
	TriageCVE(ctx context.Context, cveID string, pkgName, pkgVersion, ecosystem string, existing *memory.FindingRecord) (*TriageFinding, error)
}

// TriageProviders is the registry of providers that support per-CVE triage.
var TriageProviders = map[string]func() TriageProvider{}

// providerKinds maps provider names to the GitHub alert kinds they cover.
var providerKinds = map[string][]string{
	"github":     {"dependabot", "codeql", "secrets"},
	"dependabot": {"dependabot"},
	"codeql":     {"codeql"},
	"secrets":    {"secrets"},
}

// GetProvider returns the provider for the given name, or an error if unknown.
// For GitHub-backed providers, a GitHubClient must be supplied.
func GetProvider(name string, client *GitHubClient) (Provider, error) {
	kinds, ok := providerKinds[name]
	if !ok {
		return nil, fmt.Errorf("unknown provider %q (supported: github, dependabot, codeql, secrets)", name)
	}
	return NewGitHubMultiProvider(client, kinds), nil
}

// GetTriageProvider returns a triage-capable provider for the given name.
func GetTriageProvider(name string) (TriageProvider, error) {
	fn, ok := TriageProviders[name]
	if !ok {
		keys := make([]string, 0, len(TriageProviders))
		for k := range TriageProviders {
			keys = append(keys, k)
		}
		return nil, fmt.Errorf("unknown triage provider %q (supported: %s)", name, list(keys))
	}
	return fn(), nil
}

func list(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return s[0]
}

// ---------------------------------------------------------------------------
// TriageFinding — unified finding returned by any TriageProvider
// ---------------------------------------------------------------------------

// TriageFinding holds all triage data for a single vulnerability, aligned with
// the SKILL file memory schema.
type TriageFinding struct {
	CVEID          string
	Package        string
	Ecosystem      string
	InstalledVer   string
	FixedVer       string
	Status         string // not_affected | affected | fixed | under_investigation
	Justification  string // VEX justification for not_affected
	ActionResponse string // VEX action for affected
	Severity       string // critical | high | medium | low | unknown
	SafeHarbour    float64
	ThreatModel    *ThreatModel
	CWSS           *CWSSData
	Decision       *memory.Decision
	History        []memory.HistoryEntry
	Source         string // "vulnetix" | "github"
	ExploitCount   int
	InKEV          bool
}

// ThreatModel holds MITRE ATT&CK-derived threat modelling data.
type ThreatModel struct {
	Techniques         []string `json:"techniques,omitempty"`
	Tactics            []string `json:"tactics,omitempty"`
	AttackVector       string   `json:"attack_vector,omitempty"`
	AttackComplexity   string   `json:"attack_complexity,omitempty"`
	PrivilegesRequired string   `json:"privileges_required,omitempty"`
	UserInteraction    string   `json:"user_interaction,omitempty"`
	Reachability       string   `json:"reachability,omitempty"`
	Exposure           string   `json:"exposure,omitempty"`
}

// CWSSData holds a CWSS-derived priority score.
type CWSSData struct {
	Score    float64            `json:"score"`
	Priority string             `json:"priority,omitempty"`
	Factors  map[string]float64 `json:"factors,omitempty"`
}

// EnrichedAlert holds a provider alert with VDB enrichment data.
type EnrichedAlert struct {
	Alert       Alert           `json:"alert"`
	Remediation *map[string]any `json:"remediation,omitempty"`
	Fixes       *FixesMerged    `json:"fixes,omitempty"`
	Error       string          `json:"error,omitempty"`
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
