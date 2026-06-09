package scan

import (
	"strings"
)

// AffectedSymbols carries the lower-efficacy symbol-level fallback shipped on
// every cli.sca response (all tiers). The CLI greps local source for these
// literal names to emit a "grep-match" reachability signal when the
// higher-efficacy tree-sitter path has no queries for the CVE.
type AffectedSymbols struct {
	Routines []string
	Files    []string
	Modules  []string
}

// HasAny returns true if any list is populated.
func (a *AffectedSymbols) HasAny() bool {
	if a == nil {
		return false
	}
	return len(a.Routines) > 0 || len(a.Files) > 0 || len(a.Modules) > 0
}

// EnrichedVuln extends VulnFinding with version-filtered, enriched data. It is
// populated by SynthesiseFromCDX from the /v2/cli.sca response — the server now
// performs version filtering, exploit-intel, and remediation enrichment in the
// same round-trip, so there is no separate client-side enrichment loop.
type EnrichedVuln struct {
	VulnFinding
	Confirmed       bool    // true if installed version is in affected range
	IsMalicious     bool    // malware/malicious package — highest sort priority
	AffectedRange   string  // e.g., ">= 2.0.0, < 2.3.1"
	PathCount       int     // number of source files / transitive paths introducing this vuln
	ThreatExposure  float64 // x_threatExposure from VDB — primary sort key
	EPSSScore       float64 // displayed
	EPSSPercentile  float64 // displayed
	CVSSScore       float64 // displayed
	CoalitionESS    float64 // displayed
	ExploitIntel    *ExploitSummary
	Remediation     *RemediationInfo
	SSVCDecision    string // "Act", "Attend", "Track*", "Track"
	FixAvailability string // "available", "partial", "no_fix"
	IDSRules        []IDSRule

	// Per-source severity ratings (coerced from numeric scores / decisions).
	EPSSSeverity string // severity derived from EPSS probability
	CESSeverity  string // severity derived from Coalition ESS score
	CVSSSeverity string // severity derived from CVSS score
	SSVCSeverity string // severity derived from SSVC decision
	// MaxSeverity is the highest severity across all scoring sources for this vuln.
	// It is used for --severity threshold evaluation.
	MaxSeverity string

	// MatchMethod records how this vuln was matched to the package (e.g. "name+version", "cpe", "name-only").
	MatchMethod string

	// Reachability records the outcome of the local code-analysis pass
	// for this vuln. Values:
	//   "direct"      — vulnerable AST node lives inside the installed
	//                    package's own source (highest confidence).
	//   "transitive"  — vulnerable AST node lives in first-party code
	//                    that calls into the affected dep.
	//   "semantic"    — the lower-efficacy fallback: the affected
	//                    routine / file / module name appears literally
	//                    in your source (e.g. an import statement or
	//                    typed usage). Indicates intent to use the
	//                    affected element but not a proven call path.
	//   "unreachable" — queries ran and nothing matched.
	//   empty         — no analysis was performed (no data to compare).
	Reachability string

	// ReachabilityAssessed is true when tree-sitter queries actually ran
	// for this CVE (i.e. the CVE was in the evaluated set).
	ReachabilityAssessed bool

	// ReachabilityQueryHashes are the query hashes that ran for this CVE.
	// Populated when ReachabilityAssessed is true.
	ReachabilityQueryHashes []string

	// AffectedSymbols is the symbol-level fallback returned by the API for
	// every tier. Populated whether or not tree-sitter queries existed.
	AffectedSymbols *AffectedSymbols

	// SemanticMatches lists per-CVE source hits from the semantic
	// reachability pass — one entry per (file, line, symbol). Empty when
	// Reachability != "semantic".
	SemanticMatches []SemanticMatch
}

// SemanticMatch is one source hit produced by the semantic reachability
// fallback. The CLI's pretty-printer renders these under a Semantic
// Reachability section so users can jump straight to file:line.
type SemanticMatch struct {
	File   string
	Line   int
	Symbol string
	Kind   string // "routine" | "file" | "module"
}

// ExploitSummary captures exploit intelligence for a vulnerability.
type ExploitSummary struct {
	ExploitCount    int
	Sources         []string
	HasWeaponized   bool
	HighestMaturity string
}

// RemediationInfo captures remediation plan details.
type RemediationInfo struct {
	FixAvailability string
	FixVersion      string
	Actions         []string
}

// EnrichOptions controls optional enrichment calls. A zero value preserves the
// historical behavior: fetch affected ranges, exploit intel, and remediation.
type EnrichOptions struct {
	SkipAffected    bool
	SkipExploits    bool
	SkipRemediation bool
}

// IDSRule represents a snort or suricata detection rule.
type IDSRule struct {
	Type    string // "snort" or "suricata"
	Content string
	Source  string
	CveID   string
}

// isWildcardRange returns true if the version range means "all versions".
func isWildcardRange(vr string) bool {
	vr = strings.TrimSpace(vr)
	return vr == "*" || vr == ">= 0" || vr == ">= 0.0.0" || vr == "<= 99999"
}

// checkAffectedResponse parses the V2Affected response and determines if the
// installed version falls within any affected range for the given package.
// Returns (versionRange, isAffected, matchMethod).
//
// Matching strategy (in order):
//  1. Match by packageName (or product) and ecosystem — check all version ranges.
//  2. If no name match, try CPE-based matching using vendor/product/cpe fields.
//  3. If the API returned affected entries but none matched, the package is NOT
//     affected (return false). We tolerate false negatives over false positives.
//  4. Only when no affected data exists at all do we assume affected (true).
func checkAffectedResponse(data map[string]interface{}, pkgName, installedVer, ecosystem string) (string, bool, string) {
	affected, ok := data["affected"].([]interface{})
	if !ok || len(affected) == 0 {
		return "", true, "no-data" // no affected data at all — assume affected
	}

	// Pass 1: match by package name / product name.
	var matched bool
	var allRanges []string
	for _, a := range affected {
		am, ok := a.(map[string]interface{})
		if !ok {
			continue
		}

		name := stringVal(am, "packageName")
		if name == "" {
			name = stringVal(am, "product")
		}
		eco := stringVal(am, "ecosystem")

		if !strings.EqualFold(name, pkgName) {
			continue
		}
		if eco != "" && !strings.EqualFold(eco, ecosystem) {
			continue
		}

		matched = true

		vr := stringVal(am, "versionRange")
		if vr == "" {
			vr = stringVal(am, "versions")
		}
		if vr == "" {
			// Entry matches our package but has no range — can't rule it out,
			// but keep checking other entries.
			continue
		}

		allRanges = append(allRanges, vr)

		if isWildcardRange(vr) {
			// Wildcard — defer to fix-version check.
			return vr, true, "name+wildcard"
		}

		if IsVersionAffected(installedVer, vr, ecosystem) {
			return vr, true, "name+version"
		}
	}

	// If we found name-matched entries with version ranges but none matched
	// the installed version, the package is not affected.
	if matched && len(allRanges) > 0 {
		return strings.Join(allRanges, " | "), false, "name+version"
	}
	// Name matched but no ranges — can't determine, assume affected.
	if matched {
		return "", true, "name-only"
	}

	// Pass 2: CPE-based matching — check if any affected entry's CPE, vendor,
	// or product field matches the package name. This catches cases where the
	// VDB uses a different canonical name than the ecosystem package name.
	lowerPkg := strings.ToLower(pkgName)
	for _, a := range affected {
		am, ok := a.(map[string]interface{})
		if !ok {
			continue
		}

		if matchesByCPE(am, lowerPkg) {
			vr := stringVal(am, "versionRange")
			if vr == "" {
				vr = stringVal(am, "versions")
			}
			if vr == "" {
				return "", true, "cpe" // CPE matches but no range — assume affected
			}
			if isWildcardRange(vr) {
				return vr, true, "cpe+wildcard"
			}
			if IsVersionAffected(installedVer, vr, ecosystem) {
				return vr, true, "cpe+version"
			}
			return vr, false, "cpe+version"
		}
	}

	// Affected data exists but nothing matched our package — not affected.
	return "", false, "unmatched"
}

// matchesByCPE checks whether an affected entry's CPE, vendor, or product
// fields match the given lowercase package name.
func matchesByCPE(am map[string]interface{}, lowerPkg string) bool {
	// Check vendor and product fields directly.
	vendor := strings.ToLower(stringVal(am, "vendor"))
	product := strings.ToLower(stringVal(am, "product"))

	if product != "" && product == lowerPkg {
		return true
	}
	// Some packages are namespaced: e.g. "@angular/core" should match product "core"
	// with vendor "angular", or "org.apache.logging.log4j:log4j-core" → product "log4j-core".
	if product != "" && strings.HasSuffix(lowerPkg, product) {
		return true
	}

	// Check CPE string: cpe:2.3:a:vendor:product:...
	cpe := strings.ToLower(stringVal(am, "cpe"))
	if cpe == "" {
		cpe = strings.ToLower(stringVal(am, "cpe23"))
	}
	if cpe != "" {
		parts := strings.Split(cpe, ":")
		if len(parts) >= 5 {
			cpeVendor := parts[3]
			cpeProduct := parts[4]
			if cpeProduct == lowerPkg || cpeVendor == lowerPkg {
				return true
			}
			if strings.HasSuffix(lowerPkg, cpeProduct) {
				return true
			}
		}
	}

	_ = vendor // vendor alone is too broad to match on
	return false
}

// ParseRemediationScores extracts scores from the remediation plan response
// into the EnrichedVuln. These are displayed but not used for primary sorting.
func ParseRemediationScores(data map[string]interface{}, ev *EnrichedVuln) {
	// SSVC
	if ssvc, ok := data["ssvc"].(map[string]interface{}); ok {
		ev.SSVCDecision = stringVal(ssvc, "decision")
	}

	// Fix availability
	if fa := stringVal(data, "fixAvailability"); fa != "" {
		ev.FixAvailability = fa
	}

	// Severity object may contain scores.
	if sev, ok := data["severity"].(map[string]interface{}); ok {
		if v, ok := sev["cvssScore"].(float64); ok {
			ev.CVSSScore = v
		}
		if v, ok := sev["epssScore"].(float64); ok {
			ev.EPSSScore = v
		}
		if v, ok := sev["epssPercentile"].(float64); ok {
			ev.EPSSPercentile = v
		}
		if v, ok := sev["cessScore"].(float64); ok {
			ev.CoalitionESS = v
		}
		// Threat exposure — primary sort key.
		if v, ok := sev["x_threatExposure"].(float64); ok {
			ev.ThreatExposure = v
		}
		// Exploitation maturity for weaponized detection.
		if em, ok := sev["exploitationMaturity"].(map[string]interface{}); ok {
			level := stringVal(em, "level")
			if ev.ExploitIntel != nil && (strings.EqualFold(level, "active") || strings.EqualFold(level, "high")) {
				ev.ExploitIntel.HasWeaponized = true
			}
		}
	}

	// Malicious flag — check at top level and in severity.
	if mal, ok := data["isMalicious"].(bool); ok && mal {
		ev.IsMalicious = true
	}
}

// ComputeEnrichedSeverities fills the per-source severity fields and MaxSeverity
// on ev after all score data has been populated.
func ComputeEnrichedSeverities(ev *EnrichedVuln) {
	// CVSS: prefer the enriched CVSSScore; fall back to the raw Score on VulnFinding.
	cvssScore := ev.CVSSScore
	if cvssScore == 0 {
		cvssScore = ev.Score
	}
	if cvssScore > 0 {
		metricType := ev.MetricType
		if metricType == "" {
			metricType = "cvssv3.1"
		}
		ev.CVSSSeverity = ScoreToSeverity(metricType, cvssScore)
	}

	if ev.EPSSScore > 0 {
		ev.EPSSSeverity = ScoreToSeverity("epss", ev.EPSSScore)
	}

	if ev.CoalitionESS > 0 {
		ev.CESSeverity = ScoreToSeverity("coalition_ess", ev.CoalitionESS)
	}

	if ev.SSVCDecision != "" {
		ev.SSVCSeverity = SSVCToSeverity(ev.SSVCDecision)
	}

	// MaxSeverity: highest across all coerced severities AND the base Severity
	// field that came from the VDB search response.
	candidates := []string{
		ev.Severity,
		ev.CVSSSeverity,
		ev.EPSSSeverity,
		ev.CESSeverity,
		ev.SSVCSeverity,
	}
	best := ""
	for _, s := range candidates {
		if SeverityLevel(s) > SeverityLevel(best) {
			best = s
		}
	}
	if best == "" {
		best = "unscored"
	}
	ev.MaxSeverity = best
}

// CollectIDSRules gathers all IDS rules from enriched vulns.
func CollectIDSRules(vulns []EnrichedVuln) []IDSRule {
	var rules []IDSRule
	for _, v := range vulns {
		rules = append(rules, v.IDSRules...)
	}
	return rules
}

// stringVal safely extracts a string value from a map.
func stringVal(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
