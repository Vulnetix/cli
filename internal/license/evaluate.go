package license

import (
	"fmt"
	"strings"
)

var findingCounter int

func nextFindingID(prefix string) string {
	findingCounter++
	return fmt.Sprintf("%s-%03d", prefix, findingCounter)
}

// Evaluate runs all license evaluation rules against the detected packages.
func Evaluate(packages []PackageLicense, cfg EvalConfig) *AnalysisResult {
	findingCounter = 0

	result := &AnalysisResult{
		Mode:     cfg.Mode,
		Packages: packages,
		Summary: AnalysisSummary{
			LicenseCounts:  map[string]int{},
			CategoryCounts: map[Category]int{},
			FindingsBySev:  map[string]int{},
		},
	}

	// Build summary counts.
	for _, pkg := range packages {
		result.Summary.TotalPackages++
		result.Summary.LicenseCounts[pkg.LicenseSpdxID]++

		cat := CategoryUnknown
		if pkg.Record != nil {
			cat = pkg.Record.Category
			if pkg.Record.IsOsiApproved {
				result.Summary.OsiApproved++
			}
			if pkg.Record.IsFsfLibre {
				result.Summary.FsfLibre++
			}
			if pkg.Record.IsDeprecated {
				result.Summary.Deprecated++
			}
		}
		if pkg.LicenseSpdxID == "UNKNOWN" || strings.EqualFold(pkg.LicenseSpdxID, "non-standard") {
			cat = CategoryUnknown
			result.Summary.Unknown++
		}
		result.Summary.CategoryCounts[cat]++
	}

	// Run rules.
	var allowList *AllowList
	if len(cfg.AllowedLicenses) > 0 {
		allowList = &AllowList{Licenses: cfg.AllowedLicenses}
	}

	for i := range packages {
		pkg := &packages[i]

		// Rule: unknown-license
		if pkg.LicenseSpdxID == "UNKNOWN" {
			result.Findings = append(result.Findings, findingWithProvenance(
				nextFindingID("LICENSE-UNKNOWN"),
				fmt.Sprintf("Unknown license for %s", pkg.PackageName),
				fmt.Sprintf("No license could be detected for %s@%s from %s", pkg.PackageName, pkg.PackageVersion, pkg.Ecosystem),
				"medium", "unknown-license", 1.0, *pkg,
				[]EvidenceStep{{Rule: "unknown-license", Input: pkg.PackageName, Expected: "known SPDX ID", Actual: "UNKNOWN", Result: "FAIL"}},
			))
		}

		// Rule: non-standard license (deps.dev reports a license exists but it's not SPDX-recognized)
		if strings.EqualFold(pkg.LicenseSpdxID, "non-standard") {
			result.Findings = append(result.Findings, findingWithProvenance(
				nextFindingID("LICENSE-NONSTANDARD"),
				fmt.Sprintf("Non-standard license for %s", pkg.PackageName),
				fmt.Sprintf("%s@%s uses a non-standard license that is not an SPDX-recognized identifier", pkg.PackageName, pkg.PackageVersion),
				"low", "non-standard-license", 0.8, *pkg,
				[]EvidenceStep{{Rule: "non-standard-license", Input: pkg.PackageName, Expected: "SPDX-recognized license", Actual: "non-standard", Result: "FAIL"}},
			))
		}

		if pkg.Record == nil {
			continue
		}

		// Rule: deprecated-license
		if pkg.Record.IsDeprecated {
			result.Findings = append(result.Findings, findingWithProvenance(
				nextFindingID("LICENSE-DEPRECATED"),
				fmt.Sprintf("Deprecated license %s", pkg.LicenseSpdxID),
				fmt.Sprintf("%s@%s uses deprecated SPDX license %s (%s)", pkg.PackageName, pkg.PackageVersion, pkg.LicenseSpdxID, pkg.Record.Name),
				"low", "deprecated-license", 1.0, *pkg,
				[]EvidenceStep{{Rule: "deprecated-license", Input: pkg.LicenseSpdxID, Expected: "non-deprecated", Actual: "deprecated", Result: "FAIL"}},
			))
		}

		// Rule: not-osi-approved
		if !pkg.Record.IsOsiApproved && pkg.Record.Category != CategoryPublicDomain {
			result.Findings = append(result.Findings, findingWithProvenance(
				nextFindingID("LICENSE-NOT-OSI"),
				fmt.Sprintf("Non-OSI-approved license %s", pkg.LicenseSpdxID),
				fmt.Sprintf("%s@%s uses %s which is not OSI-approved", pkg.PackageName, pkg.PackageVersion, pkg.LicenseSpdxID),
				"low", "not-osi-approved", 1.0, *pkg,
				[]EvidenceStep{{Rule: "not-osi-approved", Input: pkg.LicenseSpdxID, Expected: "OSI-approved", Actual: "not approved", Result: "FAIL"}},
			))
		}

		// Rule: copyleft-in-production
		if pkg.Record.Category == CategoryStrongCopyleft && isProductionScope(pkg.Scope) {
			result.Findings = append(result.Findings, findingWithProvenance(
				nextFindingID("LICENSE-COPYLEFT-PROD"),
				fmt.Sprintf("Strong copyleft license %s in production", pkg.LicenseSpdxID),
				fmt.Sprintf("%s@%s uses strong copyleft license %s in production scope", pkg.PackageName, pkg.PackageVersion, pkg.LicenseSpdxID),
				"high", "copyleft-in-production", 0.9, *pkg,
				[]EvidenceStep{
					{Rule: "copyleft-in-production", Input: pkg.LicenseSpdxID, Expected: "permissive or weak-copyleft", Actual: string(pkg.Record.Category), Result: "FAIL"},
					{Rule: "scope-check", Input: pkg.Scope, Expected: "development/test", Actual: pkg.Scope, Result: "FAIL"},
				},
			))
		}

		// Rule: not-in-allowlist
		if allowList != nil && allowList.IsActive() && !allowList.Contains(pkg.LicenseSpdxID) {
			result.Findings = append(result.Findings, findingWithProvenance(
				nextFindingID("LICENSE-NOT-ALLOWED"),
				fmt.Sprintf("License %s not in allow list", pkg.LicenseSpdxID),
				fmt.Sprintf("%s@%s uses %s which is not in the approved license list", pkg.PackageName, pkg.PackageVersion, pkg.LicenseSpdxID),
				"high", "not-in-allowlist", 1.0, *pkg,
				[]EvidenceStep{{Rule: "not-in-allowlist", Input: pkg.LicenseSpdxID, Expected: fmt.Sprintf("one of: %s", strings.Join(allowList.Licenses, ", ")), Actual: pkg.LicenseSpdxID, Result: "FAIL"}},
			))
		}
	}

	// Rule: license-conflict (check all pairs)
	if cfg.Mode == "individual" {
		// Per-manifest conflict detection.
		byFile := map[string][]PackageLicense{}
		for _, pkg := range packages {
			byFile[pkg.SourceFile] = append(byFile[pkg.SourceFile], pkg)
		}
		for _, filePkgs := range byFile {
			result.Conflicts = append(result.Conflicts, detectConflicts(filePkgs)...)
		}
	} else {
		// Inclusive mode: all packages together.
		result.Conflicts = detectConflicts(packages)
	}

	// Convert conflicts to findings.
	for _, c := range result.Conflicts {
		// Merge paths from both conflicting packages.
		var allPaths [][]string
		allPaths = append(allPaths, c.Package1Paths...)
		allPaths = append(allPaths, c.Package2Paths...)
		result.Findings = append(result.Findings, Finding{
			ID:              nextFindingID("LICENSE-CONFLICT"),
			Title:           fmt.Sprintf("License conflict: %s vs %s", c.License1, c.License2),
			Description:     c.Description,
			Severity:        c.Severity,
			Confidence:      0.85,
			Package:         PackageLicense{PackageName: c.Package1},
			Category:        "license-conflict",
			IntroducedPaths: allPaths,
			PathCount:       len(allPaths),
			Evidence: []EvidenceStep{
				{Rule: "license-conflict", Input: fmt.Sprintf("%s + %s", c.License1, c.License2), Expected: "compatible", Actual: "incompatible", Result: "FAIL"},
			},
		})
	}

	result.Summary.ConflictCount = len(result.Conflicts)
	for _, f := range result.Findings {
		result.Summary.FindingsBySev[f.Severity]++
	}

	return result
}

// detectConflicts checks all distinct license pairs for incompatibilities.
func detectConflicts(packages []PackageLicense) []LicenseConflict {
	// Group packages by license.
	licensePackages := map[string][]PackageLicense{}
	for _, pkg := range packages {
		if pkg.LicenseSpdxID != "UNKNOWN" {
			licensePackages[pkg.LicenseSpdxID] = append(licensePackages[pkg.LicenseSpdxID], pkg)
		}
	}

	// Get distinct license IDs.
	var licenseIDs []string
	for id := range licensePackages {
		licenseIDs = append(licenseIDs, id)
	}

	var conflicts []LicenseConflict

	for i := 0; i < len(licenseIDs); i++ {
		for j := i + 1; j < len(licenseIDs); j++ {
			id1, id2 := licenseIDs[i], licenseIDs[j]

			// Check specific ID pair overrides first.
			if cs := IDConflict(id1, id2); cs != nil && cs.Severity != "" {
				pkgs1 := licensePackages[id1]
				pkgs2 := licensePackages[id2]
				conflicts = append(conflicts, LicenseConflict{
					Type:           "incompatible",
					Severity:       cs.Severity,
					License1:       id1,
					License2:       id2,
					Package1:       pkgs1[0].PackageName,
					Package2:       pkgs2[0].PackageName,
					Description:    cs.Description,
					Recommendation: cs.Recommendation,
					Package1Paths:  pkgs1[0].IntroducedPaths,
					Package2Paths:  pkgs2[0].IntroducedPaths,
				})
				continue
			}

			// Check category-level conflicts.
			rec1 := LookupSPDX(id1)
			rec2 := LookupSPDX(id2)
			if rec1 == nil || rec2 == nil {
				continue
			}
			if cs := CategoryConflict(rec1.Category, rec2.Category); cs != nil && cs.Severity != "" {
				pkgs1 := licensePackages[id1]
				pkgs2 := licensePackages[id2]
				conflicts = append(conflicts, LicenseConflict{
					Type:           "copyleft-mixing",
					Severity:       cs.Severity,
					License1:       id1,
					License2:       id2,
					Package1:       pkgs1[0].PackageName,
					Package2:       pkgs2[0].PackageName,
					Description:    cs.Description,
					Recommendation: cs.Recommendation,
					Package1Paths:  pkgs1[0].IntroducedPaths,
					Package2Paths:  pkgs2[0].IntroducedPaths,
				})
			}
		}
	}

	return conflicts
}

// findingWithProvenance creates a Finding and copies provenance from the package.
func findingWithProvenance(id, title, description, severity, category string, confidence float64, pkg PackageLicense, evidence []EvidenceStep) Finding {
	return Finding{
		ID:              id,
		Title:           title,
		Description:     description,
		Severity:        severity,
		Confidence:      confidence,
		Package:         pkg,
		Category:        category,
		Evidence:        evidence,
		IntroducedPaths: pkg.IntroducedPaths,
		PathCount:       pkg.PathCount,
	}
}

func isProductionScope(scope string) bool {
	switch scope {
	case "production", "runtime", "":
		return true
	}
	return false
}

// CountFindingsAtOrAbove counts findings at or above the given severity threshold.
func CountFindingsAtOrAbove(findings []Finding, threshold string) int {
	thresholdRank := severityRank(threshold)
	count := 0
	for _, f := range findings {
		if severityRank(f.Severity) <= thresholdRank {
			count++
		}
	}
	return count
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}
