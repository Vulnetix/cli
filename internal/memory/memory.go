// Package memory manages the .vulnetix/memory.yaml file that persists scan state
// between runs — last scan summary, history, and cached findings.
package memory

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	Techniques           []string              `yaml:"techniques,omitempty"`
	Tactics              []string              `yaml:"tactics,omitempty"`
	AttackVector         string                `yaml:"attack_vector,omitempty"`
	AttackComplexity     string                `yaml:"attack_complexity,omitempty"`
	PrivilegesRequired   string                `yaml:"privileges_required,omitempty"`
	UserInteraction      string                `yaml:"user_interaction,omitempty"`
	Reachability         string                `yaml:"reachability,omitempty"`
	Exposure             string                `yaml:"exposure,omitempty"`
	ReachabilityEvidence *ReachabilityEvidence `yaml:"reachability_evidence,omitempty"`
}

// ReachabilityMatch is one tree-sitter query hit recorded against a file.
// The range is "start_line:end_line" (1-indexed, inclusive) matching the
// "n:n" convention used elsewhere in CLI output.
type ReachabilityMatch struct {
	File  string `yaml:"file"`
	Range string `yaml:"range"`
	Query string `yaml:"query,omitempty"`
}

// ReachabilityEvidence is the result of a tree-sitter reachability scan
// for a single finding. Direct matches live inside the installed-package
// folder; transitive matches are first-party (or other-dep) code paths
// that reach the vulnerable symbol.
type ReachabilityEvidence struct {
	Direct     []ReachabilityMatch `yaml:"direct,omitempty"`
	Transitive []ReachabilityMatch `yaml:"transitive,omitempty"`
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

// Tool identifies which scan family produced a finding. Persisted on every
// FindingRecord / SASTFindingRecord so triage can filter by category.
const (
	ToolSCA       = "sca"
	ToolSAST      = "sast"
	ToolIaC       = "iac"
	ToolSecrets   = "secrets"
	ToolContainer = "container"
	ToolQuality   = "quality"
	ToolLicense   = "license"
)

// AllTools is the canonical list of tool tags persisted in memory.
var AllTools = []string{
	ToolSCA, ToolSAST, ToolIaC, ToolSecrets, ToolContainer, ToolQuality, ToolLicense,
}

// ScanContext is the per-scan metadata threaded into record writers so each
// finding remembers when and where it was last seen. Branch in particular is
// load-bearing for reconciliation: cross-branch scans must not auto-resolve
// findings recorded under a different branch.
type ScanContext struct {
	Branch    string
	Path      string
	Timestamp string // RFC3339 UTC; if empty, writers fill with time.Now().
}

// Location captures a code-level pointer for a finding: file + optional
// line/column range + optional snippet. Stored on FindingRecord.Locations.
type Location struct {
	File      string `yaml:"file"`
	StartLine int    `yaml:"start_line,omitempty"`
	EndLine   int    `yaml:"end_line,omitempty"`
	StartCol  int    `yaml:"start_col,omitempty"`
	EndCol    int    `yaml:"end_col,omitempty"`
	Snippet   string `yaml:"snippet,omitempty"`
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
	Tool           string         `yaml:"tool,omitempty"`   // sca | sast | iac | secrets | container | quality | license
	Locations      []Location     `yaml:"locations,omitempty"`
	LastSeenBranch string         `yaml:"last_seen_branch,omitempty"`
	LastSeenAt     string         `yaml:"last_seen_at,omitempty"`

	// Enriched scan data — populated by vulnetix scan.
	AffectedRange   string           `yaml:"affected_range,omitempty"`
	IsMalicious     bool             `yaml:"is_malicious,omitempty"`
	Confirmed       bool             `yaml:"confirmed,omitempty"`
	Scores          *ScoreData       `yaml:"scores,omitempty"`
	Exploits        *ExploitInfo     `yaml:"exploits,omitempty"`
	Remediation     *RemediationData `yaml:"remediation,omitempty"`
	InCisaKev       bool             `yaml:"in_cisa_kev,omitempty"`
	InEuKev         bool             `yaml:"in_eu_kev,omitempty"`
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
	SASTRulesLoaded  int    `yaml:"sast_rules_loaded,omitempty"`
	SASTFindingCount int    `yaml:"sast_finding_count,omitempty"`
	SARIFPath        string `yaml:"sarif_path,omitempty"`
}

// SASTFindingRecord stores triage data for a single SAST finding,
// keyed by fingerprint in the SASTFindings map.
type SASTFindingRecord struct {
	RuleID      string                 `yaml:"rule_id"`
	RuleName    string                 `yaml:"rule_name"`
	Severity    string                 `yaml:"severity"`
	FirstSeen   string                 `yaml:"first_seen"`
	LastSeen    string                 `yaml:"last_seen"`
	Status      string                 `yaml:"status"` // "open"|"resolved"|"suppressed"
	ResolvedAt  string                 `yaml:"resolved_at,omitempty"`
	ArtifactURI string                 `yaml:"artifact_uri,omitempty"`
	StartLine   int                    `yaml:"start_line,omitempty"`
	Fingerprint string                 `yaml:"fingerprint"`
	Properties  map[string]interface{} `yaml:"properties,omitempty"`
	Tool           string                 `yaml:"tool,omitempty"` // always "sast"; persisted for filter symmetry
	Locations      []Location             `yaml:"locations,omitempty"`
	LastSeenBranch string                 `yaml:"last_seen_branch,omitempty"`
	LastSeenAt     string                 `yaml:"last_seen_at,omitempty"`
}

// Memory is the top-level .vulnetix/memory.yaml structure.
type Memory struct {
	Version       string                       `yaml:"version"`
	LastScan      *ScanRecord                  `yaml:"last_scan,omitempty"`
	History       []ScanRecord                 `yaml:"history,omitempty"`
	Findings      map[string]FindingRecord     `yaml:"findings,omitempty"`       // triage findings keyed by CVE ID
	SASTFindings  map[string]SASTFindingRecord `yaml:"sast_findings,omitempty"`  // SAST findings keyed by fingerprint
	Environment   *EnvironmentContext          `yaml:"environment,omitempty"`    // last-gathered env context
	VDBQueries    []VDBQuery                   `yaml:"vdb_queries,omitempty"`    // recent VDB query log

	// scanCtx is in-memory only — never serialised. Writers read it when
	// stamping LastSeenBranch / LastSeenAt onto records.
	scanCtx *ScanContext `yaml:"-"`
}

// SetScanContext stamps subsequent record writes with the given branch/path.
// Pass nil to clear. Reset between scan runs.
func (m *Memory) SetScanContext(ctx *ScanContext) {
	m.scanCtx = ctx
}

// stampSeen sets LastSeenBranch/LastSeenAt on a FindingRecord from the
// current scan context. now is the canonical timestamp for the calling
// write batch (so all records in one batch share it).
func (m *Memory) stampSeen(now string) (branch, ts string) {
	ts = now
	if m.scanCtx != nil {
		branch = m.scanCtx.Branch
		if m.scanCtx.Timestamp != "" {
			ts = m.scanCtx.Timestamp
		}
	}
	return
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
	normalizeTools(&m)
	return &m, nil
}

// normalizeTools fills in the Tool field on records persisted before the field
// existed. The mapping is heuristic but conservative: any FindingRecord with
// Source containing "sca" or "sast" gets the corresponding tag; any record in
// SASTFindings gets "sast". Records that can't be inferred are left blank and
// will be excluded from tool-filtered queries until next write.
func normalizeTools(m *Memory) {
	if m.Findings != nil {
		for id, f := range m.Findings {
			if f.Tool != "" {
				continue
			}
			switch {
			case strings.Contains(f.Source, ToolSAST):
				f.Tool = ToolSAST
			case strings.Contains(f.Source, ToolSCA) || strings.Contains(f.Source, "vulnetix-sca") || strings.Contains(f.Source, "github") || strings.Contains(f.Source, "dependabot"):
				f.Tool = ToolSCA
			}
			m.Findings[id] = f
		}
	}
	if m.SASTFindings != nil {
		for k, f := range m.SASTFindings {
			if f.Tool == "" {
				f.Tool = ToolSAST
				m.SASTFindings[k] = f
			}
		}
	}
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

// RecordCategorizedFindings upserts findings tagged with a specific tool
// category (iac, secrets, container, quality, license). The map key is the
// finding identifier — a rule ID, secret fingerprint, license SPDX expression,
// etc. — chosen by the producer. Each FindingRecord must already have at least
// one Location populated; the function tags Tool and Status (default
// "under_investigation" for fresh records) and merges over existing entries.
func (m *Memory) RecordCategorizedFindings(tool string, findings map[string]FindingRecord) {
	if m.Findings == nil {
		m.Findings = make(map[string]FindingRecord)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	branch, ts := m.stampSeen(now)
	for id, f := range findings {
		f.Tool = tool
		f.LastSeenBranch = branch
		f.LastSeenAt = ts
		existing, hasExisting := m.Findings[id]
		if hasExisting {
			// Preserve prior triage decision and merge locations.
			f.Status = existing.Status
			f.Justification = existing.Justification
			f.ActionResponse = existing.ActionResponse
			f.Decision = existing.Decision
			f.History = existing.History
			locSet := map[string]bool{}
			merged := make([]Location, 0, len(existing.Locations)+len(f.Locations))
			for _, l := range existing.Locations {
				key := fmt.Sprintf("%s:%d:%d", l.File, l.StartLine, l.StartCol)
				if !locSet[key] {
					merged = append(merged, l)
					locSet[key] = true
				}
			}
			for _, l := range f.Locations {
				key := fmt.Sprintf("%s:%d:%d", l.File, l.StartLine, l.StartCol)
				if !locSet[key] {
					merged = append(merged, l)
					locSet[key] = true
				}
			}
			f.Locations = merged
		} else if f.Status == "" {
			f.Status = "under_investigation"
		}
		if f.Discovery == nil {
			f.Discovery = &DiscoveryInfo{Date: now, Source: "scan"}
			if len(f.Locations) > 0 {
				f.Discovery.File = f.Locations[0].File
			}
		}
		f.History = append(f.History, HistoryEntry{
			Date:   now,
			Event:  "scan",
			Detail: fmt.Sprintf("Recorded by %s scan", tool),
		})
		m.Findings[id] = f
	}
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

// toolSet builds a lookup from a tool list. A nil/empty list or one containing
// "all" returns nil, meaning "no filter".
func toolSet(tools []string) map[string]bool {
	if len(tools) == 0 {
		return nil
	}
	set := make(map[string]bool, len(tools))
	for _, t := range tools {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		if t == "all" {
			return nil
		}
		set[t] = true
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

// GetOpenFindingsByTools returns open Findings filtered to the given tool tags.
// An empty list or a list containing "all" returns every open finding.
func (m *Memory) GetOpenFindingsByTools(tools []string) map[string]FindingRecord {
	want := toolSet(tools)
	out := make(map[string]FindingRecord)
	for id, f := range m.Findings {
		switch f.Status {
		case "under_investigation", "affected":
		default:
			continue
		}
		if want != nil && !want[f.Tool] {
			continue
		}
		out[id] = f
	}
	return out
}

// GetOpenSASTFindingsByTools returns open SAST findings filtered to the given
// tool tags. Since SASTFindings only ever holds Tool="sast" records, this is a
// no-op pass-through unless the filter explicitly excludes sast.
func (m *Memory) GetOpenSASTFindingsByTools(tools []string) map[string]SASTFindingRecord {
	want := toolSet(tools)
	out := make(map[string]SASTFindingRecord)
	for k, f := range m.SASTFindings {
		if f.Status != "open" {
			continue
		}
		tool := f.Tool
		if tool == "" {
			tool = ToolSAST
		}
		if want != nil && !want[tool] {
			continue
		}
		out[k] = f
	}
	return out
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
	if rec.Tool == "" {
		rec.Tool = ToolSCA
	}
	rec.LastSeenBranch, rec.LastSeenAt = m.stampSeen(time.Now().UTC().Format(time.RFC3339))

	m.Findings[vulnID] = rec
}

// RecordReachability stores a tree-sitter reachability scan result on
// an existing finding. Passing nil clears the field; passing an empty
// evidence struct also clears it (so a clean rescan doesn't leak stale
// matches). The function is a no-op when no finding exists yet — the
// caller is expected to RecordVulnLookup first.
func (m *Memory) RecordReachability(vulnID string, evidence *ReachabilityEvidence) {
	if m.Findings == nil {
		return
	}
	rec, ok := m.Findings[vulnID]
	if !ok {
		return
	}
	if rec.ThreatModel == nil {
		rec.ThreatModel = &ThreatModel{}
	}
	if evidence == nil || (len(evidence.Direct) == 0 && len(evidence.Transitive) == 0) {
		rec.ThreatModel.ReachabilityEvidence = nil
	} else {
		rec.ThreatModel.ReachabilityEvidence = evidence
	}
	rec.History = append(rec.History, HistoryEntry{
		Date:   time.Now().UTC().Format(time.RFC3339),
		Event:  "reachability-scan",
		Detail: reachabilitySummary(evidence),
	})
	m.Findings[vulnID] = rec
}

func reachabilitySummary(ev *ReachabilityEvidence) string {
	if ev == nil {
		return "no matches"
	}
	return fmt.Sprintf("%d direct, %d transitive", len(ev.Direct), len(ev.Transitive))
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
		existing.InEuKev = f.InEuKev
		existing.PathCount = f.PathCount
		existing.Source = "vulnetix-sca"
		existing.Tool = ToolSCA
		existing.LastSeenBranch, existing.LastSeenAt = m.stampSeen(now)

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

		// Mirror SourceFiles into Locations for tool-agnostic readers.
		// Line numbers are unknown for SCA, so File-only entries are correct.
		locSet := map[string]bool{}
		for _, l := range existing.Locations {
			if l.StartLine == 0 && l.EndLine == 0 {
				locSet[l.File] = true
			}
		}
		for _, sf := range existing.SourceFiles {
			if !locSet[sf] {
				existing.Locations = append(existing.Locations, Location{File: sf})
				locSet[sf] = true
			}
		}

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
	Tool      string
	Package   string
	Ecosystem string
	OldStatus string
	NewStatus string
	Comment   string
	Finding   FindingRecord
}

// ReconcileContext drives ReconcileTool. Behaviour varies by Tool:
//
//   - sca / container: CurrentIDs is the set of CVE IDs in the current scan.
//     InstalledPkgs is "<ecosystem>:<name>"; used to distinguish
//     "dependency removed" from "patched upstream".
//   - sast / secrets / iac: CurrentIDs is the set of fingerprints emitted by
//     the current scan. Verifier is consulted before flipping a record to
//     `fixed` — if the on-disk evidence is still present (Verifier returns
//     gone=false) the record is left untouched.
//
// Records whose LastSeenBranch is non-empty and differs from ctx.Branch are
// skipped entirely — we never auto-resolve findings recorded on another
// branch during a scan of this one.
type ReconcileContext struct {
	Tool          string
	CurrentIDs    map[string]bool
	InstalledPkgs map[string]bool
	Branch        string
	RootPath      string
	Verifier      func(loc Location) (gone bool, reason string)
}

// ReconcileTool walks Findings (and SASTFindings when Tool==sast) and flips
// status based on whether each record matches the current scan results, as
// described on ReconcileContext.
func (m *Memory) ReconcileTool(ctx ReconcileContext) []StateChange {
	now := time.Now().UTC().Format(time.RFC3339)
	var changes []StateChange

	apply := func(id string, rec FindingRecord, inCurrent bool) (FindingRecord, *StateChange) {
		if rec.LastSeenBranch != "" && ctx.Branch != "" && rec.LastSeenBranch != ctx.Branch {
			return rec, nil
		}
		if !inCurrent {
			if rec.Status == "fixed" || rec.Status == "not_affected" {
				return rec, nil
			}
			var comment string
			switch ctx.Tool {
			case ToolSCA, ToolContainer:
				pkgKey := strings.ToLower(rec.Ecosystem) + ":" + strings.ToLower(rec.Package)
				if ctx.InstalledPkgs != nil && !ctx.InstalledPkgs[pkgKey] {
					comment = "Dependency removed from manifest"
				} else if ctx.InstalledPkgs == nil {
					comment = "No longer reported by upstream source"
				} else {
					comment = "Package still present but no longer flagged — patched upstream"
				}
			case ToolSAST, ToolSecrets, ToolIaC:
				if ctx.Verifier == nil || len(rec.Locations) == 0 {
					return rec, nil
				}
				gone, reason := ctx.Verifier(rec.Locations[0])
				if !gone {
					return rec, nil
				}
				comment = "Verified gone: " + reason
			default:
				return rec, nil
			}
			old := rec.Status
			rec.Status = "fixed"
			rec.History = append(rec.History, HistoryEntry{
				Date:   now,
				Event:  "auto-resolved",
				Detail: comment,
			})
			return rec, &StateChange{
				CveID:     id,
				Tool:      ctx.Tool,
				Package:   rec.Package,
				Ecosystem: rec.Ecosystem,
				OldStatus: old,
				NewStatus: "fixed",
				Comment:   comment,
				Finding:   rec,
			}
		}
		// Present in current scan — flip back from fixed if needed.
		if rec.Status == "fixed" {
			rec.Status = "under_investigation"
			rec.History = append(rec.History, HistoryEntry{
				Date:   now,
				Event:  "regression",
				Detail: "Reappeared in scan results after previously being fixed",
			})
			return rec, &StateChange{
				CveID:     id,
				Tool:      ctx.Tool,
				Package:   rec.Package,
				Ecosystem: rec.Ecosystem,
				OldStatus: "fixed",
				NewStatus: "under_investigation",
				Comment:   "Regression — reappeared in scan results after previously being fixed",
				Finding:   rec,
			}
		}
		return rec, nil
	}

	// SAST findings live in their own map; mirror their treatment via a
	// synthetic FindingRecord adapter so the same logic runs.
	if ctx.Tool == ToolSAST {
		for fp, sf := range m.SASTFindings {
			if sf.Status == "resolved" || sf.Status == "suppressed" {
				continue
			}
			if sf.Tool != "" && sf.Tool != ToolSAST {
				continue
			}
			synthetic := FindingRecord{
				Status:         sf.Status,
				Locations:      sf.Locations,
				LastSeenBranch: sf.LastSeenBranch,
			}
			if synthetic.Status == "open" {
				synthetic.Status = "affected"
			}
			updated, change := apply(fp, synthetic, ctx.CurrentIDs[fp])
			if change == nil {
				continue
			}
			if updated.Status == "fixed" {
				sf.Status = "resolved"
				sf.ResolvedAt = now
			} else if updated.Status == "under_investigation" {
				sf.Status = "open"
				sf.ResolvedAt = ""
			}
			m.SASTFindings[fp] = sf
			changes = append(changes, *change)
		}
		return changes
	}

	for id, rec := range m.Findings {
		if rec.Tool != ctx.Tool {
			continue
		}
		updated, change := apply(id, rec, ctx.CurrentIDs[id])
		if change == nil {
			continue
		}
		m.Findings[id] = updated
		changes = append(changes, *change)
	}
	return changes
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
	InEuKev          bool
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

// RecordSASTFindings upserts SAST finding records. New findings get status "open"
// and first_seen set to now. Existing findings get last_seen updated.
func (m *Memory) RecordSASTFindings(findings []SASTFindingRecord) {
	if m.SASTFindings == nil {
		m.SASTFindings = make(map[string]SASTFindingRecord)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	branch, ts := m.stampSeen(now)
	for _, f := range findings {
		f.Tool = ToolSAST
		f.LastSeenBranch = branch
		f.LastSeenAt = ts
		// Mirror flat ArtifactURI+StartLine into Locations for filter symmetry.
		if f.ArtifactURI != "" && len(f.Locations) == 0 {
			f.Locations = []Location{{File: f.ArtifactURI, StartLine: f.StartLine}}
		}
		if existing, ok := m.SASTFindings[f.Fingerprint]; ok {
			existing.LastSeen = now
			existing.LastSeenBranch = branch
			existing.LastSeenAt = ts
			existing.Tool = ToolSAST
			if len(existing.Locations) == 0 && len(f.Locations) > 0 {
				existing.Locations = f.Locations
			}
			if existing.Status == "resolved" {
				existing.Status = "open"
				existing.ResolvedAt = ""
			}
			m.SASTFindings[f.Fingerprint] = existing
		} else {
			f.FirstSeen = now
			f.LastSeen = now
			if f.Status == "" {
				f.Status = "open"
			}
			m.SASTFindings[f.Fingerprint] = f
		}
	}
}

// MarkSASTFindingResolved marks a SAST finding as resolved by fingerprint.
func (m *Memory) MarkSASTFindingResolved(fingerprint string) {
	if m.SASTFindings == nil {
		return
	}
	if rec, ok := m.SASTFindings[fingerprint]; ok {
		rec.Status = "resolved"
		rec.ResolvedAt = time.Now().UTC().Format(time.RFC3339)
		m.SASTFindings[fingerprint] = rec
	}
}
