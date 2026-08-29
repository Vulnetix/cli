package license

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// FindingID builds the stable identifier for a per-package license finding.
//
// Identifiers must survive across runs: memory reconciliation resolves a
// finding by noticing its ID has disappeared from the current result set, and
// the SARIF partialFingerprint is derived from it. A run-local counter would
// make both meaningless, since the ordinal depends on package iteration order.
//
// The SPDX id is deliberately absent: a package resolves to exactly one license
// per run, so <category>:<ecosystem>:<package>@<version> is already unique, and
// omitting it lets legacy counter-keyed memory records be migrated (a
// FindingRecord stores no license field).
func FindingID(category string, pkg PackageLicense) string {
	return fmt.Sprintf("LICENSE:%s:%s:%s@%s",
		category,
		strings.ToLower(pkg.Ecosystem),
		strings.ToLower(pkg.PackageName),
		pkg.PackageVersion,
	)
}

// ConflictFindingID builds the stable identifier for a license-conflict
// finding. The license and package pairs are each sorted so that the same
// conflict discovered from either direction yields one identifier.
func ConflictFindingID(c LicenseConflict) string {
	licenses := []string{c.License1, c.License2}
	packages := []string{c.Package1, c.Package2}
	sort.Strings(licenses)
	sort.Strings(packages)
	return fmt.Sprintf("LICENSE:license-conflict:%s|%s:%s|%s",
		licenses[0], licenses[1], packages[0], packages[1])
}

// Evaluate runs all license evaluation rules against the detected packages.
func Evaluate(packages []PackageLicense, cfg EvalConfig) *AnalysisResult {
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

	// Nil policy falls back to the defaults, which reproduce the severities
	// this evaluator used before policies existed. Adopting a policy is then a
	// deliberate act rather than something an upgrade does to a build.
	policy := cfg.Policy
	if policy == nil {
		policy = DefaultPolicy()
	}

	for i := range packages {
		pkg := &packages[i]

		// A scope the policy does not evaluate produces no findings at all.
		// Development and test dependencies are not distributed, so a copyleft
		// build tool is usually not a licence obligation — and reporting it as
		// one buries the findings that are.
		if !policy.EvaluatesScope(pkg.Scope, cfg.Project) {
			continue
		}

		// Rule: unknown-license
		if pkg.LicenseSpdxID == "UNKNOWN" {
			// The severity depends on the policy's stance: an unresolved licence
			// is a gap in the data, and whether that gap is a violation or a
			// warning is a compliance decision, not a property of the scanner.
			if sev := unknownSeverity(policy, cfg.Project); sev != "" {
				result.Findings = append(result.Findings, findingWithProvenance(
					FindingID("unknown-license", *pkg),
					fmt.Sprintf("Unknown license for %s", pkg.PackageName),
					fmt.Sprintf("No license could be detected for %s@%s from %s", pkg.PackageName, pkg.PackageVersion, pkg.Ecosystem),
					sev, "unknown-license", 1.0, *pkg,
					[]EvidenceStep{{Rule: "unknown-license", Input: pkg.PackageName, Expected: "known SPDX ID", Actual: "UNKNOWN", Result: "FAIL"}},
				))
			}
		}

		// Rule: non-standard license (deps.dev reports a license exists but it's not SPDX-recognized)
		if strings.EqualFold(pkg.LicenseSpdxID, "non-standard") {
			result.Findings = append(result.Findings, findingWithProvenance(
				FindingID("non-standard-license", *pkg),
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
				FindingID("deprecated-license", *pkg),
				fmt.Sprintf("Deprecated license %s", pkg.LicenseSpdxID),
				fmt.Sprintf("%s@%s uses deprecated SPDX license %s (%s)", pkg.PackageName, pkg.PackageVersion, pkg.LicenseSpdxID, pkg.Record.Name),
				"low", "deprecated-license", 1.0, *pkg,
				[]EvidenceStep{{Rule: "deprecated-license", Input: pkg.LicenseSpdxID, Expected: "non-deprecated", Actual: "deprecated", Result: "FAIL"}},
			))
		}

		// Rule: not-osi-approved
		if !pkg.Record.IsOsiApproved && pkg.Record.Category != CategoryPublicDomain {
			result.Findings = append(result.Findings, findingWithProvenance(
				FindingID("not-osi-approved", *pkg),
				fmt.Sprintf("Non-OSI-approved license %s", pkg.LicenseSpdxID),
				fmt.Sprintf("%s@%s uses %s which is not OSI-approved", pkg.PackageName, pkg.PackageVersion, pkg.LicenseSpdxID),
				"low", "not-osi-approved", 1.0, *pkg,
				[]EvidenceStep{{Rule: "not-osi-approved", Input: pkg.LicenseSpdxID, Expected: "OSI-approved", Actual: "not approved", Result: "FAIL"}},
			))
		}

		// Rule: category-in-production
		//
		// The category comes from the policy when it overrides the embedded
		// classification, and the severity comes from the policy's table. This
		// is what makes a policy more useful than a flat allow list: a licence
		// nobody enumerated still lands in a category, and the category still
		// has a decision attached to it.
		effectiveCat := policy.CategoryFor(pkg.LicenseSpdxID, pkg.Record.Category)
		if sev := policy.SeverityFor(effectiveCat, cfg.Project); sev != "" && isProductionScope(pkg.Scope) {
			result.Findings = append(result.Findings, findingWithProvenance(
				FindingID("copyleft-in-production", *pkg),
				fmt.Sprintf("%s license %s in production", effectiveCat, pkg.LicenseSpdxID),
				fmt.Sprintf("%s@%s uses %s, classified %s, in production scope",
					pkg.PackageName, pkg.PackageVersion, pkg.LicenseSpdxID, effectiveCat),
				sev, "copyleft-in-production", 0.9, *pkg,
				[]EvidenceStep{
					{Rule: "category-policy", Input: pkg.LicenseSpdxID, Expected: "a category the policy permits", Actual: string(effectiveCat), Result: "FAIL"},
					{Rule: "scope-check", Input: pkg.Scope, Expected: "development/test", Actual: pkg.Scope, Result: "FAIL"},
				},
			))
		}

		// Rule: not-in-allowlist
		if allowList != nil && allowList.IsActive() && !allowList.Contains(pkg.LicenseSpdxID) {
			result.Findings = append(result.Findings, findingWithProvenance(
				FindingID("not-in-allowlist", *pkg),
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
			ID:              ConflictFindingID(c),
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

	// Exceptions are applied last, over the complete finding set, so an
	// exception covers a package regardless of which rule flagged it. Applying
	// them per rule would mean an exception that silently stopped working when
	// a package tripped a different rule.
	applyExceptions(result, cfg)

	for _, f := range result.Findings {
		result.Summary.FindingsBySev[f.Severity]++
	}

	return result
}

// applyExceptions marks findings an approved exception covers.
//
// Marks, not removes. See the Finding.Exempted doc comment: a violation count
// that fell because somebody wrote an exception is a different fact from one
// that fell because the dependency was removed.
func applyExceptions(result *AnalysisResult, cfg EvalConfig) {
	now := cfg.Now
	if now.IsZero() {
		now = time.Now()
	}

	for i := range result.Findings {
		f := &result.Findings[i]
		// A conflict finding names two packages and belongs to neither, so a
		// package exception cannot speak for it.
		if f.Category == "license-conflict" {
			result.Summary.Effective++
			continue
		}

		applied, exempt := cfg.Exceptions.Match(f.Package, cfg.Project, now)
		switch {
		case exempt:
			f.Exempted = true
			f.ExemptionReason = applied.Exception.Reason
			f.ExemptionLabel = applied.Label()
			result.Summary.Exempted++
		case applied.Expired:
			// An expired exception does not exempt. Saying so is the point:
			// otherwise the finding reappears with no explanation and the user
			// has no reason to look at the expiry they wrote.
			f.ExemptionExpired = true
			f.ExemptionReason = applied.Exception.Reason
			f.ExemptionLabel = applied.Label() + " — EXPIRED"
			result.Summary.ExpiredExceptions++
			result.Summary.Effective++
		default:
			result.Summary.Effective++
		}
	}
}

// unknownSeverity resolves the severity an unresolved licence carries.
func unknownSeverity(policy *Policy, project string) string {
	switch policy.UnknownFor(project) {
	case UnknownIgnore:
		return ""
	case UnknownFail:
		// The policy's stated position is that an unidentified licence cannot
		// ship, so it is reported at the severity the policy gives the unknown
		// category — defaulting to high rather than the advisory medium.
		if sev := policy.SeverityFor(CategoryUnknown, project); sev != "" && sev != "medium" {
			return sev
		}
		return "high"
	default:
		if sev := policy.SeverityFor(CategoryUnknown, project); sev != "" {
			return sev
		}
		return "medium"
	}
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
		// An exempted finding must not breach the gate — an approved exception
		// that still failed the build would be no exception at all. It remains
		// in the report, badged; only the gate ignores it.
		if f.Exempted {
			continue
		}
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
