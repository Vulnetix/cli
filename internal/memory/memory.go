// Package memory manages the .vulnetix/memory.yaml file that persists scan state
// between runs — last scan summary, history, and cached findings.
package memory

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// FileName is the basename of the memory file inside .vulnetix/.
	FileName = "memory.yaml"
	// maxHistory is the maximum number of historical scan records to retain.
	maxHistory = 20
)

// ScopeStats records package and vulnerability counts for a single scope bucket.
type ScopeStats struct {
	Packages int `yaml:"packages"`
	Vulns    int `yaml:"vulns"`
}

// ThreatModel holds MITRE ATT&CK-derived threat modelling data.
type ThreatModel struct {
	Techniques         []string `yaml:"techniques,omitempty"`
	Tactics            []string `yaml:"tactics,omitempty"`
	AttackVector       string   `yaml:"attack_vector,omitempty"`
	AttackComplexity   string   `yaml:"attack_complexity,omitempty"`
	PrivilegesRequired string   `yaml:"privileges_required,omitempty"`
	UserInteraction    string   `yaml:"user_interaction,omitempty"`
	Reachability       string   `yaml:"reachability,omitempty"`
	Exposure           string   `yaml:"exposure,omitempty"`
}

// CWSSData holds a CWSS-derived priority score.
type CWSSData struct {
	Score    float64            `yaml:"score"`
	Priority string             `yaml:"priority,omitempty"`
	Factors  map[string]float64 `yaml:"factors,omitempty"`
}

// Decision records a user's decision about a vulnerability.
type Decision struct {
	Choice string `yaml:"choice"`
	Reason string `yaml:"reason"`
	Date   string `yaml:"date"` // RFC3339
	Actor  string `yaml:"actor,omitempty"`
}

// DiscoveryInfo records how and when a vulnerability was discovered.
type DiscoveryInfo struct {
	Date   string `yaml:"date"`
	Source string `yaml:"source"` // scan | hook | user | vulnetix-triage | github-triage
	File   string `yaml:"file,omitempty"`
	SBOM   string `yaml:"sbom,omitempty"`
}

// VersionInfo tracks package versions relevant to a finding.
type VersionInfo struct {
	Current       string `yaml:"current,omitempty"`
	CurrentSource string `yaml:"current_source,omitempty"`
	FixedIn       string `yaml:"fixed_in,omitempty"`
	FixSource     string `yaml:"fix_source,omitempty"`
}

// HistoryEntry is an append-only log entry for a finding.
type HistoryEntry struct {
	Date   string `yaml:"date"`
	Event  string `yaml:"event"`
	Detail string `yaml:"detail,omitempty"`
}

// FindingRecord stores all triage data for a single vulnerability.
// This schema is shared with the Claude Code plugin SKILL files.
type FindingRecord struct {
	Aliases        []string       `yaml:"aliases,omitempty"`
	Package        string         `yaml:"package,omitempty"`
	Ecosystem      string         `yaml:"ecosystem,omitempty"`
	Discovery      *DiscoveryInfo `yaml:"discovery,omitempty"`
	Versions       *VersionInfo   `yaml:"versions,omitempty"`
	Severity       string         `yaml:"severity,omitempty"`
	SafeHarbour    float64        `yaml:"safe_harbour,omitempty"`
	Status         string         `yaml:"status,omitempty"` // not_affected | affected | fixed | under_investigation
	Justification  string         `yaml:"justification,omitempty"`
	ActionResponse string         `yaml:"action_response,omitempty"`
	ThreatModel    *ThreatModel   `yaml:"threat_model,omitempty"`
	CWSS           *CWSSData      `yaml:"cwss,omitempty"`
	Decision       *Decision      `yaml:"decision,omitempty"`
	History        []HistoryEntry `yaml:"history,omitempty"`
	Source         string         `yaml:"source,omitempty"` // "vulnetix" | "github"
}

// ScanRecord summarises one scan run.
type ScanRecord struct {
	Timestamp      string                `yaml:"timestamp"`
	Path           string                `yaml:"path,omitempty"`
	GitBranch      string                `yaml:"git_branch,omitempty"`
	GitCommit      string                `yaml:"git_commit,omitempty"`
	GitRemote      string                `yaml:"git_remote,omitempty"`
	FilesScanned   int                   `yaml:"files_scanned"`
	Packages       int                   `yaml:"packages"`
	Vulns          int                   `yaml:"vulns"`
	Critical       int                   `yaml:"critical"`
	High           int                   `yaml:"high"`
	Medium         int                   `yaml:"medium"`
	Low            int                   `yaml:"low"`
	SBOMPath       string                `yaml:"sbom_path,omitempty"`
	ScopeBreakdown map[string]ScopeStats `yaml:"scope_breakdown,omitempty"`
	IDSRulesPath   string                `yaml:"ids_rules_path,omitempty"`
	IDSRulesCount  int                   `yaml:"ids_rules_count,omitempty"`
}

// Memory is the top-level .vulnetix/memory.yaml structure.
type Memory struct {
	Version  string                   `yaml:"version"`
	LastScan *ScanRecord              `yaml:"last_scan,omitempty"`
	History  []ScanRecord             `yaml:"history,omitempty"`
	Findings map[string]FindingRecord `yaml:"findings,omitempty"` // triage findings keyed by CVE ID
}

// Load reads memory.yaml from the given .vulnetix directory.
// If the file does not exist, a fresh Memory is returned without error.
// If the file is corrupt, a fresh Memory is returned (non-fatal).
func Load(vulnetixDir string) (*Memory, error) {
	path := filepath.Join(vulnetixDir, FileName)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Memory{Version: "1"}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	var m Memory
	if err := yaml.Unmarshal(data, &m); err != nil {
		// Silently recover from corrupt files; a fresh scan will overwrite.
		return &Memory{Version: "1"}, nil
	}
	if m.Version == "" {
		m.Version = "1"
	}
	return &m, nil
}

// Save writes m to memory.yaml inside vulnetixDir, creating the directory if needed.
func Save(vulnetixDir string, m *Memory) error {
	if err := os.MkdirAll(vulnetixDir, 0o755); err != nil {
		return fmt.Errorf("failed to create %s: %w", vulnetixDir, err)
	}

	path := filepath.Join(vulnetixDir, FileName)
	data, err := yaml.Marshal(m)
	if err != nil {
		return fmt.Errorf("failed to marshal memory: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	return nil
}

// RecordScan prepends rec to History, sets LastScan, and trims history to maxHistory.
// If rec.Timestamp is empty it is set to the current UTC time.
func (m *Memory) RecordScan(rec ScanRecord) {
	if rec.Timestamp == "" {
		rec.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	m.LastScan = &rec
	m.History = append([]ScanRecord{rec}, m.History...)
	if len(m.History) > maxHistory {
		m.History = m.History[:maxHistory]
	}
}

// GetFinding returns the triage finding for a given CVE ID, or nil if none exists.
func (m *Memory) GetFinding(cveID string) *FindingRecord {
	if m.Findings == nil {
		return nil
	}
	if f, ok := m.Findings[cveID]; ok {
		return &f
	}
	// Also check by aliases.
	for _, f := range m.Findings {
		for _, alias := range f.Aliases {
			if alias == cveID {
				return &f
			}
		}
	}
	return nil
}

// SetFinding stores or updates triage data for a CVE ID.
func (m *Memory) SetFinding(cveID string, data FindingRecord) {
	if m.Findings == nil {
		m.Findings = make(map[string]FindingRecord)
	}
	m.Findings[cveID] = data
}
