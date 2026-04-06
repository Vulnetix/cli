package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/vulnetix/cli/internal/cdx"
	"github.com/vulnetix/cli/internal/display"
	"github.com/vulnetix/cli/internal/scan"
	"github.com/vulnetix/cli/internal/vdb"
)

// LoadFromMemory reconstructs the scan pretty output from .vulnetix/sbom.cdx.json.
// When fresh* flags are true, selective API calls are made to refresh that data.
func LoadFromMemory(rootPath string, freshExploits, freshAdvisories, freshVulns bool) error {
	sbomPath := filepath.Join(rootPath, ".vulnetix", "sbom.cdx.json")

	data, err := os.ReadFile(sbomPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no scan memory found: %s does not exist (run 'vulnetix scan' first)", sbomPath)
		}
		return fmt.Errorf("failed to read BOM: %w", err)
	}

	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return fmt.Errorf("failed to parse BOM: %w", err)
	}

	if len(bom.Vulnerabilities) == 0 {
		fmt.Fprintln(os.Stderr, "No vulnerabilities recorded in BOM (scan may have found none).")
		return nil
	}

	// Build component lookup: bom-ref → Component.
	compLookup := map[string]cdx.Component{}
	for _, c := range bom.Components {
		compLookup[c.BOMRef] = c
	}

	// Convert each CDX vuln → EnrichedVuln.
	var enrichedVulns []scan.EnrichedVuln
	for i := range bom.Vulnerabilities {
		ev := cdxToEnrichedVuln(&bom.Vulnerabilities[i], compLookup)
		if ev != nil {
			enrichedVulns = append(enrichedVulns, *ev)
		}
	}

	if len(enrichedVulns) == 0 {
		fmt.Fprintln(os.Stderr, "No vulnerabilities could be reconstructed from BOM.")
		return nil
	}

	// ── Fresh data refetch (sequential: vulns first, then advisories, then exploits). ──
	t := display.NewTerminal()

	if freshVulns {
		fmt.Fprintf(os.Stderr, "Fetching fresh vulnerability data for %d %s...\n",
			len(enrichedVulns), pluralise("vulnerability", len(enrichedVulns)))
		fetchFreshVulns(enrichedVulns)
		fmt.Fprintf(os.Stderr, "  %s vulnerability data updated\n", display.CheckMark(t))
	}

	if freshAdvisories {
		fmt.Fprintf(os.Stderr, "Fetching fresh remediation plans for %d %s...\n",
			len(enrichedVulns), pluralise("vulnerability", len(enrichedVulns)))
		fetchFreshAdvisories(enrichedVulns)
		fmt.Fprintf(os.Stderr, "  %s remediation plans updated\n", display.CheckMark(t))
	}

	if freshExploits {
		uniqueCVEs := uniqueCVEs(enrichedVulns)
		fmt.Fprintf(os.Stderr, "Fetching fresh exploit intel for %d %s...\n",
			len(uniqueCVEs), pluralise("vulnerability", len(uniqueCVEs)))
		fetchFreshExploits(enrichedVulns, uniqueCVEs)
		fmt.Fprintf(os.Stderr, "  %s exploit intel updated\n", display.CheckMark(t))
	}

	// ── Re-compute severities after any fresh data. ──
	for i := range enrichedVulns {
		scan.ComputeEnrichedSeverities(&enrichedVulns[i])
	}

	// ── Build display data. ──
	manifestGroups := buildGroupsFromMemory(enrichedVulns)
	allPackages := buildPackagesFromMemory(bom.Components)

	// ── Print pretty summary (same renderer as full scan). ──
	printPrettyScanSummary(
		enrichedVulns,
		manifestGroups,
		allPackages,
		false, // showPaths — dep graph not reconstructed
		false, // noExploits
		false, // noRemediation
		sbomPath,
		filepath.Join(rootPath, ".vulnetix"),
		"", // rulesPath
		"", // severityThreshold
	)

	return nil
}

// cdxToEnrichedVuln converts a CycloneDX vulnerability entry back to EnrichedVuln.
func cdxToEnrichedVuln(bv *cdx.Vulnerability, compLookup map[string]cdx.Component) *scan.EnrichedVuln {
	ev := &scan.EnrichedVuln{
		VulnFinding: scan.VulnFinding{
			CveID: bv.ID,
		},
		Confirmed: true,
	}

	// Parse properties.
	for _, p := range bv.Properties {
		switch p.Name {
		case "vulnetix:source-file":
			ev.VulnFinding.SourceFile = p.Value
		case "vulnetix:ecosystem":
			ev.VulnFinding.Ecosystem = p.Value
		case "vulnetix:scope":
			ev.VulnFinding.Scope = p.Value
		case "vulnetix:ssvc-decision":
			ev.SSVCDecision = p.Value
		case "vulnetix:max-severity":
			ev.MaxSeverity = p.Value
		case "vulnetix:affected-range":
			ev.AffectedRange = p.Value
		case "vulnetix:fix-availability":
			ev.FixAvailability = p.Value
		case "vulnetix:fix-version":
			ev.Remediation = &scan.RemediationInfo{FixVersion: p.Value}
		case "vulnetix:malware":
			ev.IsMalicious = p.Value == "true"
		case "vulnetix:in-cisa-kev":
			ev.VulnFinding.InCisaKev = p.Value == "true"
		case "vulnetix:in-vulncheck-kev":
			ev.VulnFinding.InVulnCheckKev = p.Value == "true"
		}
	}

	// Get package info from Affects → component lookup.
	for _, aff := range bv.Affects {
		comp, ok := compLookup[aff.Ref]
		if !ok {
			continue
		}
		ev.VulnFinding.PackageName = comp.Name
		ev.VulnFinding.PackageVer = comp.Version
		if ev.VulnFinding.Ecosystem == "" {
			for _, p := range comp.Properties {
				if p.Name == "vulnetix:ecosystem" {
					ev.VulnFinding.Ecosystem = p.Value
					break
				}
			}
		}
		break
	}

	// Parse ratings for scores.
	for _, r := range bv.Ratings {
		src := ""
		if r.Source != nil {
			src = r.Source.Name
		}
		switch src {
		case "NVD":
			ev.CVSSScore = r.Score
			ev.CVSSSeverity = r.Severity
			if ev.VulnFinding.MetricType == "" {
				ev.VulnFinding.MetricType = r.Method
			}
			if ev.VulnFinding.Severity == "" {
				ev.VulnFinding.Severity = r.Severity
			}
			if ev.VulnFinding.Score == 0 && r.Score > 0 {
				ev.VulnFinding.Score = r.Score
			}
		case "EPSS":
			ev.EPSSScore = r.Score
			ev.EPSSSeverity = r.Severity
		case "Coalition ESS":
			ev.CoalitionESS = r.Score
			ev.CESSeverity = r.Severity
		case "SSVC":
			ev.SSVCSeverity = r.Severity
		}
	}

	// If no SSVC decision, infer from SSVCSeverity.
	if ev.SSVCDecision == "" && ev.SSVCSeverity != "" {
		ev.SSVCDecision = inferSSVCDecision(ev.SSVCSeverity)
	}

	ev.ThreatExposure = computeThreatExposure(ev)
	ev.PathCount = 1

	return ev
}

// computeThreatExposure derives a sorting-appropriate exposure score
// from available enriched scores so threat ordering matches live scan.
func computeThreatExposure(ev *scan.EnrichedVuln) float64 {
	if ev.CVSSScore > 0 {
		return ev.CVSSScore
	}
	if ev.CoalitionESS > 0 {
		return ev.CoalitionESS
	}
	if ev.EPSSScore > 0 {
		return ev.EPSSScore
	}
	if ev.VulnFinding.Score > 0 {
		return ev.VulnFinding.Score
	}
	switch strings.ToLower(ev.MaxSeverity) {
	case "critical":
		return 9.0
	case "high":
		return 7.5
	case "medium":
		return 5.0
	case "low":
		return 2.5
	default:
		return 1.0
	}
}

// fetchFreshVulns calls V2Affected per vuln and updates confirmed/affectedRange.
func fetchFreshVulns(vulns []scan.EnrichedVuln) {
	client := newEnrichmentClient()
	sem := make(chan struct{}, 3)
	var wg sync.WaitGroup

	for i := range vulns {
		v := &vulns[i]
		if v.CveID == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			affected, err := client.V2Affected(v.CveID, vdb.V2QueryParams{
				Ecosystem:   v.Ecosystem,
				PackageName: v.PackageName,
			})
			if err == nil {
				recheckAffected(v.VulnFinding.PackageVer, v.VulnFinding.PackageName, affected, v)
			}
		}()
	}

	wg.Wait()
}

// recheckAffected is like checkAffectedResponse from enrich.go but updates in-place.
func recheckAffected(installedVer, pkgName string, data map[string]interface{}, ev *scan.EnrichedVuln) {
	affected, ok := data["affected"].([]interface{})
	if !ok || len(affected) == 0 {
		return
	}

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
		if eco != "" && !strings.EqualFold(eco, ev.Ecosystem) {
			continue
		}

		vr := stringVal(am, "versionRange")
		if vr == "" {
			vr = stringVal(am, "versions")
		}
		ev.AffectedRange = vr
		if vr != "" {
			ev.Confirmed = scan.IsVersionAffected(installedVer, vr, ev.Ecosystem)
		}
		return
	}
}

// fetchFreshAdvisories calls V2RemediationPlan per vuln.
func fetchFreshAdvisories(vulns []scan.EnrichedVuln) {
	client := newEnrichmentClient()
	sem := make(chan struct{}, 3)
	var wg sync.WaitGroup

	for i := range vulns {
		v := &vulns[i]
		if v.CveID == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			remData, err := client.V2RemediationPlan(v.CveID, vdb.V2RemediationParams{
				V2QueryParams: vdb.V2QueryParams{
					Ecosystem:   v.Ecosystem,
					PackageName: v.PackageName,
				},
				CurrentVersion: v.PackageVer,
			})
			if err == nil {
				rem := parseRemediationFromAPI(remData)
				v.Remediation = rem
				scan.ParseRemediationScores(remData, v)
			}
		}()
	}

	wg.Wait()
}

// parseRemediationFromAPI builds RemediationInfo from remediation plan response.
func parseRemediationFromAPI(data map[string]interface{}) *scan.RemediationInfo {
	ri := &scan.RemediationInfo{
		FixAvailability: stringVal(data, "fixAvailability"),
	}
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

// fetchFreshExploits calls GetExploits per unique CVE ID.
func fetchFreshExploits(vulns []scan.EnrichedVuln, uniqueCVEs []string) {
	client := newSearchClient()

	// Index vulns by CVE ID.
	cveIndex := map[string][]*scan.EnrichedVuln{}
	for i := range vulns {
		if vulns[i].CveID != "" {
			cveIndex[vulns[i].CveID] = append(cveIndex[vulns[i].CveID], &vulns[i])
		}
	}

	sem := make(chan struct{}, 3)
	var wg sync.WaitGroup

	for _, cveID := range uniqueCVEs {
		wg.Add(1)
		sem <- struct{}{}
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()

			exploitData, err := client.GetExploits(id)
			if err != nil {
				return
			}

			exploitIntel := parseExploitFromAPI(exploitData)
			idsRules := extractIDSRulesFromAPI(exploitData, id)

			for _, v := range cveIndex[id] {
				v.ExploitIntel = exploitIntel
				v.IDSRules = idsRules
			}
		}(cveID)
	}

	wg.Wait()
}

// parseExploitFromAPI mirrors scan.parseExploitSummary (unexported).
func parseExploitFromAPI(data map[string]interface{}) *scan.ExploitSummary {
	es := &scan.ExploitSummary{}
	if ec, ok := data["exploitCount"].(float64); ok {
		es.ExploitCount = int(ec)
	} else if ec, ok := data["count"].(float64); ok {
		es.ExploitCount = int(ec)
	}
	if summary, ok := data["summary"].(map[string]interface{}); ok {
		for source, count := range summary {
			if c, ok := count.(float64); ok && c > 0 {
				es.Sources = append(es.Sources, source)
			}
		}
	}
	if exploits, ok := data["exploits"].([]interface{}); ok {
		for _, exp := range exploits {
			em, ok := exp.(map[string]interface{})
			if !ok {
				continue
			}
			maturity := strings.ToLower(stringVal(em, "maturity"))
			if maturity == "weaponized" || maturity == "functional" {
				es.HasWeaponized = true
			}
			if es.HighestMaturity == "" || maturityRanking(maturity) < maturityRanking(strings.ToLower(es.HighestMaturity)) {
				es.HighestMaturity = stringVal(em, "maturity")
			}
		}
	}
	return es
}

// maturityRanking matches scan.maturityRank (lower = more dangerous).
func maturityRanking(m string) int {
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

// extractIDSRulesFromAPI mirrors scan.extractIDSRules (unexported).
func extractIDSRulesFromAPI(data map[string]interface{}, cveID string) []scan.IDSRule {
	var rules []scan.IDSRule
	for _, key := range []string{"idsRules", "ids_rules", "detectionRules", "detection_rules"} {
		if ruleList, ok := data[key].([]interface{}); ok {
			for _, r := range ruleList {
				rm, ok := r.(map[string]interface{})
				if !ok {
					continue
				}
				rule := scan.IDSRule{
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
					rules = append(rules, scan.IDSRule{
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

// uniqueCVEs returns deduplicated CVE IDs from enriched vulns.
func uniqueCVEs(vulns []scan.EnrichedVuln) []string {
	seen := map[string]bool{}
	var result []string
	for _, v := range vulns {
		if v.CveID != "" && !seen[v.CveID] {
			seen[v.CveID] = true
			result = append(result, v.CveID)
		}
	}
	return result
}

// buildGroupsFromMemory creates ManifestGroup entries by correlating vulns
// with the files that source them.
func buildGroupsFromMemory(vulns []scan.EnrichedVuln) []scan.ManifestGroup {
	// Collect unique source files.
	fileSet := map[string]bool{}
	for _, v := range vulns {
		if v.SourceFile != "" {
			fileSet[v.SourceFile] = true
		}
	}
	if len(fileSet) == 0 {
		// Fallback: single group with no file info.
		return []scan.ManifestGroup{}
	}

	// Build filePackages map from vulns (we don't have full package data,
	// but BuildManifestGroups needs it).  We'll seed it from vuln entries.
	filePkgs := map[string][]scan.ScopedPackage{}
	for _, v := range vulns {
		if v.SourceFile == "" {
			continue
		}
		pkg := scan.ScopedPackage{
			Name:       v.PackageName,
			Version:    v.PackageVer,
			Ecosystem:  v.Ecosystem,
			SourceFile: v.SourceFile,
		}
		filePkgs[v.SourceFile] = append(filePkgs[v.SourceFile], pkg)
	}

	fileEco := map[string]string{}
	for f, pkgs := range filePkgs {
		if len(pkgs) > 0 && pkgs[0].Ecosystem != "" {
			fileEco[f] = pkgs[0].Ecosystem
		}
	}

	return scan.BuildManifestGroups(filePkgs, fileEco)
}

// buildPackagesFromMemory creates []ScopedPackage from CDX components.
func buildPackagesFromMemory(components []cdx.Component) []scan.ScopedPackage {
	pkgs := make([]scan.ScopedPackage, 0, len(components))
	for _, c := range components {
		pkgs = append(pkgs, buildPkgFromComponent(c))
	}
	return pkgs
}

// buildPkgFromComponent creates a ScopedPackage from a CDX component.
func buildPkgFromComponent(c cdx.Component) scan.ScopedPackage {
	pkg := scan.ScopedPackage{
		Name:    c.Name,
		Version: c.Version,
	}
	for _, p := range c.Properties {
		switch p.Name {
		case "vulnetix:ecosystem":
			pkg.Ecosystem = p.Value
		case "vulnetix:scope":
			pkg.Scope = p.Value
		case "vulnetix:source-file":
			pkg.SourceFile = p.Value
		}
	}
	return pkg
}

// inferSSVCDecision maps severity back to SSVC decision for reconstruction.
func inferSSVCDecision(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "Act"
	case "high":
		return "Attend"
	case "medium":
		return "Track*"
	case "low":
		return "Track"
	default:
		return "Track"
	}
}

// stringVal safely extracts a string value from a map.
func stringVal(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
