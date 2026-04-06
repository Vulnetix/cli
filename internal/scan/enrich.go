package scan

import (
	"context"
	"strings"
	"sync"

	"github.com/vulnetix/cli/internal/vdb"
)

// EnrichedVuln extends VulnFinding with version-filtered, enriched data.
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

// IDSRule represents a snort or suricata detection rule.
type IDSRule struct {
	Type    string // "snort" or "suricata"
	Content string
	Source  string
	CveID   string
}

// EnrichVulns filters vulnerabilities by affected version range (via V2Affected),
// fetches exploit intelligence and remediation plans, and deduplicates by (CveID, PkgName).
func EnrichVulns(
	ctx context.Context,
	v1Client *vdb.Client,
	v2Client *vdb.Client,
	findings []VulnFinding,
	packages []ScopedPackage,
	concurrency int,
	progress func(done, total int),
) ([]EnrichedVuln, error) {
	if concurrency <= 0 {
		concurrency = 5
	}

	// Deduplicate findings by (CveID, PkgName) and count paths.
	type dedupKey struct {
		CveID   string
		PkgName string
	}
	type dedupEntry struct {
		finding   VulnFinding
		pathCount int
	}
	deduped := map[dedupKey]*dedupEntry{}
	var orderedKeys []dedupKey

	for _, f := range findings {
		dk := dedupKey{f.CveID, f.PackageName}
		if entry, ok := deduped[dk]; ok {
			entry.pathCount++
		} else {
			deduped[dk] = &dedupEntry{finding: f, pathCount: 1}
			orderedKeys = append(orderedKeys, dk)
		}
	}

	total := len(orderedKeys)
	if total == 0 {
		return nil, nil
	}

	type enrichResult struct {
		idx      int
		enriched *EnrichedVuln
	}
	resultsCh := make(chan enrichResult, total)
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var doneCount int
	var doneMu sync.Mutex

	for i, dk := range orderedKeys {
		if ctx.Err() != nil {
			break
		}
		entry := deduped[dk]
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, f VulnFinding, pathCount int) {
			defer wg.Done()
			defer func() { <-sem }()

			ev := enrichOne(ctx, v1Client, v2Client, f, packages)
			if ev != nil {
				ev.PathCount = pathCount
				resultsCh <- enrichResult{idx: idx, enriched: ev}
			}

			doneMu.Lock()
			doneCount++
			if progress != nil {
				progress(doneCount, total)
			}
			doneMu.Unlock()
		}(i, entry.finding, entry.pathCount)
	}

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	// Collect results preserving order for determinism.
	indexed := make(map[int]*EnrichedVuln)
	for r := range resultsCh {
		indexed[r.idx] = r.enriched
	}

	var result []EnrichedVuln
	for i := 0; i < total; i++ {
		if ev, ok := indexed[i]; ok {
			result = append(result, *ev)
		}
	}
	return result, nil
}

// enrichOne processes a single VulnFinding: checks affected version, fetches exploits
// and remediation plan. Returns nil if the installed version is not affected.
func enrichOne(
	ctx context.Context,
	v1Client *vdb.Client,
	v2Client *vdb.Client,
	f VulnFinding,
	packages []ScopedPackage,
) *EnrichedVuln {
	ev := &EnrichedVuln{
		VulnFinding: f,
		Confirmed:   true,
	}

	// ── 1. Check affected version range ────────────────────────────────
	if v2Client != nil && f.CveID != "" {
		affected, err := v2Client.V2Affected(f.CveID, vdb.V2QueryParams{
			Ecosystem:   f.Ecosystem,
			PackageName: f.PackageName,
		})
		if err == nil {
			versionRange, confirmed := checkAffectedResponse(affected, f.PackageName, f.PackageVer, f.Ecosystem)
			ev.AffectedRange = versionRange
			if versionRange != "" && !confirmed {
				return nil // installed version is NOT in affected range
			}
		}
		// If the call fails, keep the vuln (err on side of caution).
	}

	// ── 2. Fetch exploit intelligence ──────────────────────────────────
	if v1Client != nil && f.CveID != "" {
		exploitData, err := v1Client.GetExploits(f.CveID)
		if err == nil {
			ev.ExploitIntel = parseExploitSummary(exploitData)
			ev.IDSRules = extractIDSRules(exploitData, f.CveID)
		}
	}

	// ── 3. Fetch remediation plan ──────────────────────────────────────
	if v2Client != nil && f.CveID != "" {
		remParams := vdb.V2RemediationParams{}
		remParams.Ecosystem = f.Ecosystem
		remParams.PackageName = f.PackageName
		remParams.CurrentVersion = f.PackageVer
		remData, err := v2Client.V2RemediationPlan(f.CveID, remParams)
		if err == nil {
			ev.Remediation = parseRemediationInfo(remData)
			ParseRemediationScores(remData, ev)
		}
	}

	// ── 4. Compute per-source severities and MaxSeverity ───────────────
	ComputeEnrichedSeverities(ev)

	return ev
}

// checkAffectedResponse parses the V2Affected response and determines if the
// installed version falls within any affected range for the given package.
// Returns (versionRange, isAffected). If no matching entry is found, returns ("", true)
// to err on the side of caution.
func checkAffectedResponse(data map[string]interface{}, pkgName, installedVer, ecosystem string) (string, bool) {
	affected, ok := data["affected"].([]interface{})
	if !ok || len(affected) == 0 {
		return "", true // no affected data — assume affected
	}

	for _, a := range affected {
		am, ok := a.(map[string]interface{})
		if !ok {
			continue
		}

		// Match by package name or product name.
		name := stringVal(am, "packageName")
		if name == "" {
			name = stringVal(am, "product")
		}
		eco := stringVal(am, "ecosystem")

		// Check if this entry matches our package.
		if !strings.EqualFold(name, pkgName) {
			continue
		}
		if eco != "" && !strings.EqualFold(eco, ecosystem) {
			continue
		}

		vr := stringVal(am, "versionRange")
		if vr == "" {
			vr = stringVal(am, "versions")
		}
		if vr == "" {
			return "", true // no range specified — assume affected
		}

		if IsVersionAffected(installedVer, vr, ecosystem) {
			return vr, true
		}
		return vr, false
	}

	return "", true // no matching entry — assume affected
}

// parseExploitSummary extracts exploit intelligence summary from the GetExploits response.
func parseExploitSummary(data map[string]interface{}) *ExploitSummary {
	es := &ExploitSummary{}

	if ec, ok := data["exploitCount"].(float64); ok {
		es.ExploitCount = int(ec)
	} else if ec, ok := data["count"].(float64); ok {
		es.ExploitCount = int(ec)
	}

	// Source breakdown from summary.
	if summary, ok := data["summary"].(map[string]interface{}); ok {
		for source, count := range summary {
			if c, ok := count.(float64); ok && c > 0 {
				es.Sources = append(es.Sources, source)
			}
		}
	}

	// Detailed exploits array — check for weaponized maturity.
	if exploits, ok := data["exploits"].([]interface{}); ok {
		for _, exp := range exploits {
			em, ok := exp.(map[string]interface{})
			if !ok {
				continue
			}
			maturity := stringVal(em, "maturity")
			maturityLower := strings.ToLower(maturity)
			if maturityLower == "weaponized" || maturityLower == "functional" {
				es.HasWeaponized = true
			}
			if es.HighestMaturity == "" || maturityRank(maturityLower) < maturityRank(strings.ToLower(es.HighestMaturity)) {
				es.HighestMaturity = maturity
			}
		}
	}

	return es
}

// maturityRank returns a rank for exploit maturity (lower = more dangerous).
func maturityRank(m string) int {
	switch m {
	case "weaponized":
		return 0
	case "functional":
		return 1
	case "poc":
		return 2
	case "unproven":
		return 3
	default:
		return 4
	}
}

// parseRemediationInfo extracts remediation details from V2RemediationPlan response.
func parseRemediationInfo(data map[string]interface{}) *RemediationInfo {
	ri := &RemediationInfo{}

	ri.FixAvailability = stringVal(data, "fixAvailability")

	// Extract SSVC and fix version from actions.
	if actions, ok := data["actions"].([]interface{}); ok {
		for _, act := range actions {
			am, ok := act.(map[string]interface{})
			if !ok {
				continue
			}
			title := stringVal(am, "title")
			if title != "" {
				ri.Actions = append(ri.Actions, title)
			}
		}
	}

	return ri
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

// extractIDSRules looks for snort/suricata rules in the exploit response.
func extractIDSRules(data map[string]interface{}, cveID string) []IDSRule {
	var rules []IDSRule

	// Check for dedicated IDS/detection rules section.
	for _, key := range []string{"idsRules", "ids_rules", "detectionRules", "detection_rules"} {
		if ruleList, ok := data[key].([]interface{}); ok {
			for _, r := range ruleList {
				if rm, ok := r.(map[string]interface{}); ok {
					rule := IDSRule{
						Type:    stringVal(rm, "type"),
						Content: stringVal(rm, "content"),
						Source:  stringVal(rm, "source"),
						CveID:   cveID,
					}
					if rule.Content != "" {
						rules = append(rules, rule)
					}
				}
			}
		}
	}

	// Check individual exploits for embedded rules.
	if exploits, ok := data["exploits"].([]interface{}); ok {
		for _, exp := range exploits {
			em, ok := exp.(map[string]interface{})
			if !ok {
				continue
			}
			expType := strings.ToLower(stringVal(em, "type"))
			source := strings.ToLower(stringVal(em, "source"))
			if expType == "snort" || expType == "suricata" || source == "snort" || source == "suricata" {
				content := stringVal(em, "content")
				if content == "" {
					content = stringVal(em, "rule")
				}
				if content != "" {
					rules = append(rules, IDSRule{
						Type:    expType,
						Content: content,
						Source:  source,
						CveID:   cveID,
					})
				}
			}
		}
	}

	return rules
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
