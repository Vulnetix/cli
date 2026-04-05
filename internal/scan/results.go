package scan

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// ScanTask tracks one file's lifecycle through upload -> poll -> results.
type ScanTask struct {
	File        DetectedFile
	ScanID      string
	Status      string // "queued","uploading","uploaded","polling","complete","error"
	UploadStart time.Time
	UploadEnd   time.Time
	PollStart   time.Time
	PollEnd     time.Time
	Error       error
	RawResult   map[string]interface{}
	Vulns       []VulnSummary
}

// UploadDuration returns the time spent uploading.
func (t *ScanTask) UploadDuration() time.Duration {
	if t.UploadEnd.IsZero() {
		if t.UploadStart.IsZero() {
			return 0
		}
		return time.Since(t.UploadStart)
	}
	return t.UploadEnd.Sub(t.UploadStart)
}

// PollDuration returns the time spent polling.
func (t *ScanTask) PollDuration() time.Duration {
	if t.PollEnd.IsZero() {
		if t.PollStart.IsZero() {
			return 0
		}
		return time.Since(t.PollStart)
	}
	return t.PollEnd.Sub(t.PollStart)
}

// TotalDuration returns the total time from upload start to poll completion.
func (t *ScanTask) TotalDuration() time.Duration {
	if t.UploadStart.IsZero() {
		return 0
	}
	end := t.PollEnd
	if end.IsZero() {
		end = t.UploadEnd
	}
	if end.IsZero() {
		return time.Since(t.UploadStart)
	}
	return end.Sub(t.UploadStart)
}

// VulnSummary is a parsed vulnerability from scan results.
type VulnSummary struct {
	VulnID      string
	IsMalicious bool
	Scores      []ScoreEntry // ordered: EPSS > Coalition ESS > CVSSv4 > CVSS3 > CVSS2
	Severity    string
	PackageName string
	PackageVer  string
	SourceFile  string // which scanned file this came from
	// Lazy-loaded detail fields (nil until fetched)
	Exploits    *map[string]interface{}
	Timeline    *map[string]interface{}
	Fixes       *FixesMerged
	Remediation *map[string]interface{}
	Advisories  *map[string]interface{}
	Workarounds *map[string]interface{}
	Kev         *map[string]interface{}
}

// TopScore returns the highest-priority score, or 0 if none.
func (v *VulnSummary) TopScore() (string, float64) {
	if len(v.Scores) == 0 {
		return "", 0
	}
	return v.Scores[0].Type, v.Scores[0].Score
}

// ScoreEntry represents a single vulnerability score.
type ScoreEntry struct {
	Type   string  // "epss","coalition_ess","cvssv4","cvssv3.1","cvssv3.0","cvssv2"
	Score  float64
	Source string
}

// FixesMerged holds merged fix data from three V2 endpoints.
type FixesMerged struct {
	Registry      map[string]interface{}
	Distributions map[string]interface{}
	Source        map[string]interface{}
}

// scoreTypePriority defines the preference order for score types.
var scoreTypePriority = map[string]int{
	"epss":           0,
	"coalition_ess":  1,
	"cvssv4":         2,
	"cvss4":          2,
	"cvssv3.1":       3,
	"cvss3.1":        3,
	"cvssv3.0":       4,
	"cvss3.0":        4,
	"cvss3":          4,
	"cvssv3":         4,
	"cvssv2":         5,
	"cvss2":          5,
	"cvssv2.0":       5,
}

// ParseVulnsFromScanResult extracts vulnerability summaries from a scan status API response.
func ParseVulnsFromScanResult(raw map[string]interface{}, sourceFile string) []VulnSummary {
	var vulns []VulnSummary

	// The scan result may contain vulnerabilities in various structures.
	// Try common response shapes.
	vulnList := extractVulnList(raw)
	for _, v := range vulnList {
		vMap, ok := v.(map[string]interface{})
		if !ok {
			continue
		}

		summary := VulnSummary{
			SourceFile: sourceFile,
		}

		// Extract vuln ID
		if id, ok := vMap["vulnId"].(string); ok {
			summary.VulnID = id
		} else if id, ok := vMap["id"].(string); ok {
			summary.VulnID = id
		} else if id, ok := vMap["cveId"].(string); ok {
			summary.VulnID = id
		}

		// Extract malicious flag
		if mal, ok := vMap["isMalicious"].(bool); ok {
			summary.IsMalicious = mal
		}

		// Extract package info
		if pkg, ok := vMap["packageName"].(string); ok {
			summary.PackageName = pkg
		} else if pkg, ok := vMap["package"].(string); ok {
			summary.PackageName = pkg
		}
		if ver, ok := vMap["version"].(string); ok {
			summary.PackageVer = ver
		} else if ver, ok := vMap["packageVersion"].(string); ok {
			summary.PackageVer = ver
		}

		// Extract severity
		if sev, ok := vMap["severity"].(string); ok {
			summary.Severity = sev
		}

		// Extract scores
		summary.Scores = extractScores(vMap)

		// Derive severity from scores if not set
		if summary.Severity == "" {
			summary.Severity = deriveSeverity(summary.Scores)
		}

		vulns = append(vulns, summary)
	}

	return vulns
}

// extractVulnList finds the vulnerability array in the API response.
func extractVulnList(raw map[string]interface{}) []interface{} {
	// Try "vulnerabilities" key
	if list, ok := raw["vulnerabilities"].([]interface{}); ok {
		return list
	}
	// Try "results" key
	if list, ok := raw["results"].([]interface{}); ok {
		return list
	}
	// Try "data" key
	if list, ok := raw["data"].([]interface{}); ok {
		return list
	}
	// Try "findings" key
	if list, ok := raw["findings"].([]interface{}); ok {
		return list
	}
	return nil
}

// extractScores pulls score entries from a vulnerability map and sorts by preference.
func extractScores(vMap map[string]interface{}) []ScoreEntry {
	var scores []ScoreEntry

	// Try "scores" array
	if scoreList, ok := vMap["scores"].([]interface{}); ok {
		for _, s := range scoreList {
			sMap, ok := s.(map[string]interface{})
			if !ok {
				continue
			}
			entry := ScoreEntry{}
			if t, ok := sMap["type"].(string); ok {
				entry.Type = strings.ToLower(t)
			}
			if v, ok := sMap["score"].(float64); ok {
				entry.Score = v
			}
			if src, ok := sMap["source"].(string); ok {
				entry.Source = src
			}
			if entry.Type != "" {
				scores = append(scores, entry)
			}
		}
	}

	// Try "metrics" map
	if metrics, ok := vMap["metrics"].(map[string]interface{}); ok {
		for metricType, metricData := range metrics {
			mMap, ok := metricData.(map[string]interface{})
			if !ok {
				continue
			}
			entry := ScoreEntry{Type: strings.ToLower(metricType)}
			if v, ok := mMap["score"].(float64); ok {
				entry.Score = v
			} else if v, ok := mMap["baseScore"].(float64); ok {
				entry.Score = v
			}
			if src, ok := mMap["source"].(string); ok {
				entry.Source = src
			}
			if entry.Score > 0 {
				scores = append(scores, entry)
			}
		}
	}

	// Try individual score fields
	if epss, ok := vMap["epss"].(float64); ok {
		scores = append(scores, ScoreEntry{Type: "epss", Score: epss})
	}
	if ess, ok := vMap["coalitionEss"].(float64); ok {
		scores = append(scores, ScoreEntry{Type: "coalition_ess", Score: ess})
	}
	if cvss, ok := vMap["cvssV4"].(float64); ok {
		scores = append(scores, ScoreEntry{Type: "cvssv4", Score: cvss})
	}
	if cvss, ok := vMap["cvssV3"].(float64); ok {
		scores = append(scores, ScoreEntry{Type: "cvssv3.1", Score: cvss})
	}
	if cvss, ok := vMap["cvssV2"].(float64); ok {
		scores = append(scores, ScoreEntry{Type: "cvssv2", Score: cvss})
	}

	// Sort by preference order
	sort.Slice(scores, func(i, j int) bool {
		pi := scorePriority(scores[i].Type)
		pj := scorePriority(scores[j].Type)
		return pi < pj
	})

	return scores
}

func scorePriority(t string) int {
	if p, ok := scoreTypePriority[t]; ok {
		return p
	}
	return 99
}

// deriveSeverity determines severity label from scores.
func deriveSeverity(scores []ScoreEntry) string {
	for _, s := range scores {
		sev := ScoreToSeverity(s.Type, s.Score)
		if sev != "" && sev != "unscored" {
			return sev
		}
	}
	return "unscored"
}

// ScoreToSeverity converts a numeric score of a given type to a severity label.
// Supported types: epss, coalition_ess (cess), cvss* variants.
// Returns "unscored" when the type is unrecognised or the score is zero.
func ScoreToSeverity(scoreType string, score float64) string {
	t := strings.ToLower(scoreType)
	switch {
	case t == "epss":
		// EPSS is a probability 0–1.
		switch {
		case score >= 0.9:
			return "critical"
		case score >= 0.5:
			return "high"
		case score >= 0.1:
			return "medium"
		case score > 0:
			return "low"
		default:
			return "unscored"
		}
	case t == "coalition_ess" || t == "cess":
		// Coalition ESS is 0–10, same bands as CVSS.
		switch {
		case score >= 9.0:
			return "critical"
		case score >= 7.0:
			return "high"
		case score >= 4.0:
			return "medium"
		case score > 0:
			return "low"
		default:
			return "unscored"
		}
	case strings.HasPrefix(t, "cvss"):
		// All CVSS variants use the NVD severity bands (0–10 scale).
		switch {
		case score >= 9.0:
			return "critical"
		case score >= 7.0:
			return "high"
		case score >= 4.0:
			return "medium"
		case score > 0:
			return "low"
		default:
			return "unscored"
		}
	default:
		return "unscored"
	}
}

// SSVCToSeverity maps an SSVC decision string to an approximate severity label.
// SSVC decisions are: Act, Attend, Track*, Track, Defer.
func SSVCToSeverity(decision string) string {
	switch strings.ToLower(decision) {
	case "act":
		return "critical"
	case "attend":
		return "high"
	case "track*":
		return "medium"
	case "track":
		return "low"
	case "defer":
		return "low"
	default:
		return "unscored"
	}
}

// SeverityLevel returns a numeric level for severity (higher = more severe).
// This is the inverse of SeverityRank and is used for threshold comparisons.
//
//	unscored → 0
//	low      → 1
//	medium   → 2
//	high     → 3
//	critical → 4
func SeverityLevel(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default: // unscored, info, unknown, ""
		return 0
	}
}

// SeverityMeetsThreshold reports whether the given severity meets or exceeds
// the threshold severity.  "unscored" never triggers the threshold.
// Examples:
//
//	SeverityMeetsThreshold("critical", "high")  → true
//	SeverityMeetsThreshold("medium",   "high")  → false
//	SeverityMeetsThreshold("high",     "high")  → true
//	SeverityMeetsThreshold("unscored", "low")   → false
func SeverityMeetsThreshold(severity, threshold string) bool {
	level := SeverityLevel(severity)
	if level == 0 {
		return false // unscored never matches
	}
	return level >= SeverityLevel(threshold)
}

// SeverityRank returns a numeric rank for severity (lower = more severe).
// Kept for backward-compatibility; prefer SeverityLevel for threshold logic.
func SeverityRank(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "info", "informational":
		return 4
	default:
		return 5
	}
}

// ValidSeverityThresholds lists the accepted --severity flag values in ascending order.
var ValidSeverityThresholds = []string{"low", "medium", "high", "critical"}

// ScanSummary aggregates results across all tasks.
type ScanSummary struct {
	TotalFiles    int
	TotalVulns    int
	MalwareCount  int
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
	ErrorCount    int
}

// Summarize computes a summary from completed scan tasks.
func Summarize(tasks []*ScanTask) ScanSummary {
	s := ScanSummary{TotalFiles: len(tasks)}
	for _, t := range tasks {
		if t.Error != nil {
			s.ErrorCount++
			continue
		}
		for _, v := range t.Vulns {
			s.TotalVulns++
			if v.IsMalicious {
				s.MalwareCount++
			}
			switch strings.ToLower(v.Severity) {
			case "critical":
				s.CriticalCount++
			case "high":
				s.HighCount++
			case "medium":
				s.MediumCount++
			case "low":
				s.LowCount++
			}
		}
	}
	return s
}

// FormatSummary returns a human-readable summary string.
func (s ScanSummary) FormatSummary() string {
	parts := []string{
		fmt.Sprintf("%d files scanned", s.TotalFiles),
		fmt.Sprintf("%d vulnerabilities", s.TotalVulns),
	}
	if s.MalwareCount > 0 {
		parts = append(parts, fmt.Sprintf("%d malware", s.MalwareCount))
	}
	if s.CriticalCount > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", s.CriticalCount))
	}
	if s.HighCount > 0 {
		parts = append(parts, fmt.Sprintf("%d high", s.HighCount))
	}
	if s.MediumCount > 0 {
		parts = append(parts, fmt.Sprintf("%d medium", s.MediumCount))
	}
	if s.LowCount > 0 {
		parts = append(parts, fmt.Sprintf("%d low", s.LowCount))
	}
	if s.ErrorCount > 0 {
		parts = append(parts, fmt.Sprintf("%d errors", s.ErrorCount))
	}
	return strings.Join(parts, " | ")
}

// AllVulns returns all vulnerabilities across all tasks, sorted by severity.
func AllVulns(tasks []*ScanTask) []VulnSummary {
	var all []VulnSummary
	for _, t := range tasks {
		all = append(all, t.Vulns...)
	}
	sort.Slice(all, func(i, j int) bool {
		ri := SeverityRank(all[i].Severity)
		rj := SeverityRank(all[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return all[i].VulnID < all[j].VulnID
	})
	return all
}
