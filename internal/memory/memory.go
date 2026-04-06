// Package memory manages the .vulnetix/memory.yaml file that persists scan state
// between runs — last scan summary, history, and cached findings.
package memory

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// FileName is the basename of the memory file inside .vulnetix/.
	FileName = "memory.yaml"
	// maxHistory is the maximum number of historical scan records to retain.
	maxHistory = 20
	// maxVDBQueries is the maximum number of VDB query log entries to retain.
	maxVDBQueries = 50
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

// ExploitInfo captures exploit intelligence stored in memory.
type ExploitInfo struct {
	ExploitCount    int      `yaml:"exploit_count,omitempty"`
	Sources         []string `yaml:"sources,omitempty"`
	HasWeaponized   bool     `yaml:"has_weaponized,omitempty"`
	HighestMaturity string   `yaml:"highest_maturity,omitempty"`
}

// ScoreData captures all scoring sources for a vulnerability.
type ScoreData struct {
	CVSSScore      float64 `yaml:"cvss_score,omitempty"`
	CVSSSeverity   string  `yaml:"cvss_severity,omitempty"`
	EPSSScore      float64 `yaml:"epss_score,omitempty"`
	EPSSPercentile float64 `yaml:"epss_percentile,omitempty"`
	EPSSSeverity   string  `yaml:"epss_severity,omitempty"`
	CoalitionESS   float64 `yaml:"coalition_ess,omitempty"`
	CESSeverity    string  `yaml:"ces_severity,omitempty"`
	SSVCDecision   string  `yaml:"ssvc_decision,omitempty"`
	SSVCSeverity   string  `yaml:"ssvc_severity,omitempty"`
	ThreatExposure float64 `yaml:"threat_exposure,omitempty"`
	MaxSeverity    string  `yaml:"max_severity,omitempty"`
}

// RemediationData captures remediation info stored in memory.
type RemediationData struct {
	FixAvailability string   `yaml:"fix_availability,omitempty"` // available | partial | no_fix
	FixVersion      string   `yaml:"fix_version,omitempty"`
	Actions         []string `yaml:"actions,omitempty"`
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
	Source         string         `yaml:"source,omitempty"` // "vulnetix-sca" | "github"

	// Enriched scan data — populated by vulnetix scan.
	AffectedRange   string           `yaml:"affected_range,omitempty"`
	IsMalicious     bool             `yaml:"is_malicious,omitempty"`
	Confirmed       bool             `yaml:"confirmed,omitempty"`
	Scores          *ScoreData       `yaml:"scores,omitempty"`
	Exploits        *ExploitInfo     `yaml:"exploits,omitempty"`
	Remediation     *RemediationData `yaml:"remediation,omitempty"`
	InCisaKev       bool             `yaml:"in_cisa_kev,omitempty"`
	SourceFiles     []string         `yaml:"source_files,omitempty"`     // manifest files where this vuln was introduced
	PathCount       int              `yaml:"path_count,omitempty"`       // number of dependency paths introducing this vuln
	IntroducedPaths [][]string       `yaml:"introduced_paths,omitempty"` // dependency chains e.g. [[direct-dep, intermediate, vuln-pkg]]
}

// EnvironmentContext captures the auto-gathered or flag-provided context
// for a VDB query session. This schema is shared with the Claude Code plugin.
type EnvironmentContext struct {
	Platform        string `yaml:"platform,omitempty"`
	GitLocalDir     string `yaml:"git_local_dir,omitempty"`
	GitBranch       string `yaml:"git_branch,omitempty"`
	GitCommit       string `yaml:"git_commit,omitempty"`
	GitRemoteURL    string `yaml:"remote_url,omitempty"`
	GitRemoteBranch string `yaml:"remote_branch,omitempty"`
	CommitterName   string `yaml:"committer_name,omitempty"`
	CommitterEmail  string `yaml:"committer_email,omitempty"`
	GithubOrg       string `yaml:"github_org,omitempty"`
	GithubRepo      string `yaml:"github_repo,omitempty"`
	GithubPR        string `yaml:"github_pr,omitempty"`
	PackageManager  string `yaml:"package_manager,omitempty"`
	ManifestFormat  string `yaml:"manifest_format,omitempty"`
}

// VDBQuery records a single VDB API query in the memory log.
type VDBQuery struct {
	Timestamp  string `yaml:"timestamp"`
	Command    string `yaml:"command"`        // e.g. "vuln", "fixes", "exploits"
	Args       string `yaml:"args,omitempty"` // e.g. "CVE-2021-44228"
	APIVersion string `yaml:"api_version,omitempty"`
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
	Version     string                   `yaml:"version"`
	LastScan    *ScanRecord              `yaml:"last_scan,omitempty"`
	History     []ScanRecord             `yaml:"history,omitempty"`
	Findings    map[string]FindingRecord `yaml:"findings,omitempty"`    // triage findings keyed by CVE ID
	Environment *EnvironmentContext      `yaml:"environment,omitempty"` // last-gathered env context
	VDBQueries  []VDBQuery               `yaml:"vdb_queries,omitempty"` // recent VDB query log
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

// RecordVDBQuery prepends a VDB query to the log, capping at maxVDBQueries.
func (m *Memory) RecordVDBQuery(q VDBQuery) {
	if q.Timestamp == "" {
		q.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	m.VDBQueries = append([]VDBQuery{q}, m.VDBQueries...)
	if len(m.VDBQueries) > maxVDBQueries {
		m.VDBQueries = m.VDBQueries[:maxVDBQueries]
	}
}

// UpdateEnvironment replaces the stored environment context.
func (m *Memory) UpdateEnvironment(env *EnvironmentContext) {
	m.Environment = env
}

// GetOpenFindings returns all findings that haven't reached a resolved state.
// "Open" means status is "under_investigation" or "affected" — i.e. not
// "not_affected" or "fixed". These are the findings that still need triage.
func (m *Memory) GetOpenFindings() map[string]FindingRecord {
	open := make(map[string]FindingRecord)
	for id, f := range m.Findings {
		switch f.Status {
		case "under_investigation", "affected":
			open[id] = f
		}
	}
	return open
}

// RecordVulnLookup upserts a FindingRecord from a VDB vuln response.
// It extracts the vulnId, aliases, severity, and scores from the opaque API
// response data. This is best-effort; missing fields are silently skipped.
func (m *Memory) RecordVulnLookup(vulnID string, data interface{}) {
	if m.Findings == nil {
		m.Findings = make(map[string]FindingRecord)
	}

	existing := m.GetFinding(vulnID)
	var rec FindingRecord
	if existing != nil {
		rec = *existing
	}

	dataMap := extractVulnMap(data)
	if dataMap != nil {
		if sev, ok := extractString(dataMap, "maxSeverity"); ok {
			rec.Severity = sev
		} else if sev, ok := extractString(dataMap, "severity"); ok {
			rec.Severity = sev
		}

		if aliases, ok := extractStringSlice(dataMap, "aliases"); ok && len(aliases) > 0 {
			rec.Aliases = aliases
		}

		if safeHarbour, ok := extractFloat(dataMap, "safeHarbour"); ok {
			rec.SafeHarbour = safeHarbour
		}
	}

	rec.History = append(rec.History, HistoryEntry{
		Date:   time.Now().UTC().Format(time.RFC3339),
		Event:  "vdb-lookup",
		Detail: "Queried VDB for vulnerability details",
	})
	rec.Source = "vulnetix-sca"

	m.Findings[vulnID] = rec
}

// RecordEnrichedFindings upserts FindingRecords from enriched scan results.
// Each finding is keyed by CVE ID. Existing triage decisions are preserved —
// only enrichment data (scores, exploits, versions, source files) is updated.
func (m *Memory) RecordEnrichedFindings(findings []EnrichedFinding) {
	if m.Findings == nil {
		m.Findings = make(map[string]FindingRecord)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, f := range findings {
		existing, hasExisting := m.Findings[f.CveID]
		if !hasExisting {
			existing = FindingRecord{
				Status: "under_investigation",
			}
		}

		// Always update enrichment data from scan.
		existing.Package = f.PackageName
		existing.Ecosystem = f.Ecosystem
		existing.Severity = f.MaxSeverity
		existing.AffectedRange = f.AffectedRange
		existing.IsMalicious = f.IsMalicious
		existing.Confirmed = f.Confirmed
		existing.InCisaKev = f.InCisaKev
		existing.PathCount = f.PathCount
		existing.Source = "vulnetix-sca"

		// Merge source files (deduplicated).
		fileSet := map[string]bool{}
		for _, sf := range existing.SourceFiles {
			fileSet[sf] = true
		}
		for _, sf := range f.SourceFiles {
			fileSet[sf] = true
		}
		existing.SourceFiles = make([]string, 0, len(fileSet))
		for sf := range fileSet {
			existing.SourceFiles = append(existing.SourceFiles, sf)
		}
		sort.Strings(existing.SourceFiles)

		// Introduced dependency paths.
		if len(f.IntroducedPaths) > 0 {
			existing.IntroducedPaths = f.IntroducedPaths
		}

		// Version info.
		if existing.Versions == nil {
			existing.Versions = &VersionInfo{}
		}
		existing.Versions.Current = f.InstalledVersion
		if f.FixVersion != "" {
			existing.Versions.FixedIn = f.FixVersion
			existing.Versions.FixSource = "vulnetix-scan"
		}

		// Scores.
		existing.Scores = &ScoreData{
			CVSSScore:      f.CVSSScore,
			CVSSSeverity:   f.CVSSSeverity,
			EPSSScore:      f.EPSSScore,
			EPSSPercentile: f.EPSSPercentile,
			EPSSSeverity:   f.EPSSSeverity,
			CoalitionESS:   f.CoalitionESS,
			CESSeverity:    f.CESSeverity,
			SSVCDecision:   f.SSVCDecision,
			SSVCSeverity:   f.SSVCSeverity,
			ThreatExposure: f.ThreatExposure,
			MaxSeverity:    f.MaxSeverity,
		}

		// Exploit intel.
		if f.ExploitInfo != nil {
			existing.Exploits = f.ExploitInfo
		}

		// Remediation.
		if f.Remediation != nil {
			existing.Remediation = f.Remediation
		}

		// Discovery info — only set on first discovery.
		if existing.Discovery == nil {
			existing.Discovery = &DiscoveryInfo{
				Date:   now,
				Source: "scan",
			}
			if len(f.SourceFiles) > 0 {
				existing.Discovery.File = f.SourceFiles[0]
			}
		}

		// Append scan event to history.
		existing.History = append(existing.History, HistoryEntry{
			Date:   now,
			Event:  "scan",
			Detail: "Updated by vulnetix scan",
		})

		m.Findings[f.CveID] = existing
	}
}

// StateChange describes a finding whose status changed during reconciliation.
type StateChange struct {
	CveID     string
	Package   string
	Ecosystem string
	OldStatus string
	NewStatus string
	Comment   string
	Finding   FindingRecord
}

// ReconcileFindings compares the set of CVE IDs found in the current scan
// against all existing findings with source "vulnetix-sca" in memory.
//
// Findings present in memory but absent from the current scan are marked
// "fixed" (user remediated). Findings previously marked "fixed" that reappear
// in the current scan are marked "under_investigation" (regression).
//
// Returns a list of state changes so the caller can generate VEX entries.
func (m *Memory) ReconcileFindings(currentCVEs map[string]bool) []StateChange {
	if m.Findings == nil {
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339)
	var changes []StateChange

	for cveID, rec := range m.Findings {
		if rec.Source != "vulnetix-sca" {
			continue
		}

		inCurrentScan := currentCVEs[cveID]

		if !inCurrentScan && rec.Status != "fixed" && rec.Status != "not_affected" {
			// Was present before, not in current scan → user remediated.
			oldStatus := rec.Status
			rec.Status = "fixed"
			rec.History = append(rec.History, HistoryEntry{
				Date:   now,
				Event:  "auto-resolved",
				Detail: "Vulnerability disappeared from scan results; marked as user-remediated",
			})
			m.Findings[cveID] = rec
			changes = append(changes, StateChange{
				CveID:     cveID,
				Package:   rec.Package,
				Ecosystem: rec.Ecosystem,
				OldStatus: oldStatus,
				NewStatus: "fixed",
				Comment:   "User remediated — disappeared from scanner report",
				Finding:   rec,
			})
		} else if inCurrentScan && rec.Status == "fixed" {
			// Was fixed but reappeared → regression.
			rec.Status = "under_investigation"
			rec.History = append(rec.History, HistoryEntry{
				Date:   now,
				Event:  "regression",
				Detail: "Vulnerability reappeared in scan results after being marked fixed",
			})
			m.Findings[cveID] = rec
			changes = append(changes, StateChange{
				CveID:     cveID,
				Package:   rec.Package,
				Ecosystem: rec.Ecosystem,
				OldStatus: "fixed",
				NewStatus: "under_investigation",
				Comment:   "Regression — reappeared in scan results after previously being fixed",
				Finding:   rec,
			})
		}
	}

	return changes
}

// EnrichedFinding is the input struct for RecordEnrichedFindings.
// It is a flat representation of data extracted from scan enrichment.
type EnrichedFinding struct {
	CveID            string
	PackageName      string
	InstalledVersion string
	Ecosystem        string
	MaxSeverity      string
	AffectedRange    string
	IsMalicious      bool
	Confirmed        bool
	InCisaKev        bool
	PathCount        int
	SourceFiles      []string
	IntroducedPaths  [][]string

	// Scores
	CVSSScore      float64
	CVSSSeverity   string
	EPSSScore      float64
	EPSSPercentile float64
	EPSSSeverity   string
	CoalitionESS   float64
	CESSeverity    string
	SSVCDecision   string
	SSVCSeverity   string
	ThreatExposure float64

	// Fix
	FixVersion  string
	ExploitInfo *ExploitInfo
	Remediation *RemediationData
}

// extractVulnMap attempts to get a map from the opaque GetCVE response.
// The response can be a map[string]interface{} directly, or an array wrapping one.
func extractVulnMap(data interface{}) map[string]interface{} {
	if m, ok := data.(map[string]interface{}); ok {
		return m
	}
	if arr, ok := data.([]interface{}); ok && len(arr) > 0 {
		if m, ok := arr[0].(map[string]interface{}); ok {
			return m
		}
	}
	return nil
}

func extractString(m map[string]interface{}, key string) (string, bool) {
	v, ok := m[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func extractFloat(m map[string]interface{}, key string) (float64, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	default:
		return 0, false
	}
}

func extractStringSlice(m map[string]interface{}, key string) ([]string, bool) {
	v, ok := m[key]
	if !ok {
		return nil, false
	}
	arr, ok := v.([]interface{})
	if !ok {
		return nil, false
	}
	var result []string
	for _, item := range arr {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result, len(result) > 0
}
