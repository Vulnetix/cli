package cdx

import (
	"fmt"
	"strings"

	"github.com/vulnetix/cli/internal/depsdev"
)

// AdvisoriesToVulns converts deps.dev advisory data into CycloneDX vulnerability entries.
// It deduplicates against existingIDs (CVE/GHSA IDs already found by VDB) and
// uses compRefs to link vulnerabilities to affected components.
//
// compRefs maps "name@version" to the component's bom-ref in the CDX BOM.
func AdvisoriesToVulns(enrichments []depsdev.PackageEnrichment, existingIDs map[string]bool, compRefs map[string]string) []Vulnerability {
	if existingIDs == nil {
		existingIDs = map[string]bool{}
	}

	// Track which advisory IDs we've already emitted to avoid duplicates
	// when multiple packages reference the same advisory.
	emitted := map[string]bool{}
	var vulns []Vulnerability

	for _, e := range enrichments {
		if e.Error != nil {
			continue
		}
		for _, adv := range e.Advisories {
			id := adv.AdvisoryKey.ID
			if id == "" {
				continue
			}

			// Skip if this advisory (or any of its aliases) was already found by VDB.
			if depsdev.IsKnown(id, adv.Aliases, existingIDs) {
				continue
			}

			// Skip if we already emitted this advisory for another package.
			if emitted[id] {
				continue
			}
			emitted[id] = true

			vuln := Vulnerability{
				BOMRef:      id,
				ID:          id,
				Description: adv.Title,
				Source: &Source{
					Name: "deps.dev",
					URL:  "https://deps.dev",
				},
			}

			// CVSS rating.
			if adv.CVSS3Score > 0 {
				vuln.Ratings = append(vuln.Ratings, Rating{
					Score:    adv.CVSS3Score,
					Severity: depsdev.NormalizeSeverity(adv.Severity),
					Method:   "CVSSv31",
					Source:   &Source{Name: "deps.dev"},
				})
			} else if adv.Severity != "" {
				vuln.Ratings = append(vuln.Ratings, Rating{
					Severity: depsdev.NormalizeSeverity(adv.Severity),
					Method:   "other",
					Source:   &Source{Name: "deps.dev"},
				})
			}

			// Link to affected component.
			compKey := e.Name + "@" + e.Version
			if ref, ok := compRefs[compKey]; ok {
				vuln.Affects = append(vuln.Affects, Affect{Ref: ref})
			}

			// Advisory URL.
			if adv.URL != "" {
				vuln.Advisories = append(vuln.Advisories, Advisory{URL: adv.URL})
			}

			// Properties.
			vuln.Properties = append(vuln.Properties, Property{
				Name:  "vulnetix:source",
				Value: "deps.dev",
			})
			if len(adv.Aliases) > 0 {
				vuln.Properties = append(vuln.Properties, Property{
					Name:  "vulnetix:aliases",
					Value: strings.Join(adv.Aliases, ","),
				})
			}
			vuln.Properties = append(vuln.Properties, Property{
				Name:  "vulnetix:ecosystem",
				Value: e.Ecosystem,
			})

			vulns = append(vulns, vuln)
		}
	}
	return vulns
}

// SignalsToVulns generates CDX vulnerability entries for supply-chain risk signals:
// low OpenSSF Scorecard scores, missing SLSA provenance, and outdated packages.
//
// compRefs maps "name@version" to the component's bom-ref.
func SignalsToVulns(enrichments []depsdev.PackageEnrichment, compRefs map[string]string) []Vulnerability {
	var vulns []Vulnerability
	vulns = append(vulns, scorecardVulns(enrichments, compRefs)...)
	vulns = append(vulns, provenanceVulns(enrichments, compRefs)...)
	vulns = append(vulns, outdatedVulns(enrichments, compRefs)...)
	return vulns
}

// scorecardVulns generates vulnerabilities for packages with low OpenSSF Scorecard scores.
func scorecardVulns(enrichments []depsdev.PackageEnrichment, compRefs map[string]string) []Vulnerability {
	seen := map[string]bool{}
	var vulns []Vulnerability

	for _, e := range enrichments {
		if e.Project == nil || e.Project.Scorecard == nil {
			continue
		}
		sc := e.Project.Scorecard
		if sc.OverallScore >= 4.0 {
			continue // only flag scores below 4.0
		}

		// Deduplicate by project (multiple versions of same package share a project).
		projectID := ""
		if e.Project.ProjectKey.ID != "" {
			projectID = e.Project.ProjectKey.ID
		} else {
			projectID = e.Ecosystem + "/" + e.Name
		}
		if seen[projectID] {
			continue
		}
		seen[projectID] = true

		id := fmt.Sprintf("SCORECARD:%s/%s", strings.ToLower(e.Ecosystem), e.Name)
		severity := depsdev.ScorecardSeverity(sc.OverallScore)

		vuln := Vulnerability{
			BOMRef:      id,
			ID:          id,
			Description: fmt.Sprintf("OpenSSF Scorecard score %.1f/10 — supply-chain risk", sc.OverallScore),
			Source: &Source{
				Name: "OpenSSF Scorecard",
				URL:  "https://scorecard.dev",
			},
			Ratings: []Rating{{
				Score:    sc.OverallScore,
				Severity: severity,
				Method:   "other",
				Source:   &Source{Name: "OpenSSF Scorecard"},
			}},
		}

		compKey := e.Name + "@" + e.Version
		if ref, ok := compRefs[compKey]; ok {
			vuln.Affects = append(vuln.Affects, Affect{Ref: ref})
		}

		vuln.Properties = append(vuln.Properties,
			Property{Name: "vulnetix:signal-type", Value: "scorecard"},
			Property{Name: "vulnetix:scorecard-score", Value: fmt.Sprintf("%.1f", sc.OverallScore)},
			Property{Name: "vulnetix:scorecard-date", Value: sc.Date},
			Property{Name: "vulnetix:source", Value: "deps.dev"},
		)

		// Add individual check scores.
		for _, check := range sc.Checks {
			vuln.Properties = append(vuln.Properties, Property{
				Name:  fmt.Sprintf("vulnetix:scorecard-check/%s", strings.ToLower(check.Name)),
				Value: fmt.Sprintf("%d", check.Score),
			})
		}

		vulns = append(vulns, vuln)
	}
	return vulns
}

// provenanceVulns generates low-severity signals for packages missing SLSA provenance.
// Only flags packages when at least some packages in the batch DO have provenance.
func provenanceVulns(enrichments []depsdev.PackageEnrichment, compRefs map[string]string) []Vulnerability {
	hasProvenance := 0
	for _, e := range enrichments {
		if e.VersionData != nil && len(e.VersionData.SLSAProvenances) > 0 {
			hasProvenance++
		}
	}
	if hasProvenance == 0 {
		return nil
	}

	var vulns []Vulnerability
	for _, e := range enrichments {
		if e.VersionData == nil || len(e.VersionData.SLSAProvenances) > 0 {
			continue
		}

		id := fmt.Sprintf("NO-PROVENANCE:%s/%s@%s", strings.ToLower(e.Ecosystem), e.Name, e.Version)
		vuln := Vulnerability{
			BOMRef:      id,
			ID:          id,
			Description: fmt.Sprintf("No SLSA provenance attestation for %s@%s", e.Name, e.Version),
			Source: &Source{
				Name: "deps.dev",
				URL:  "https://deps.dev",
			},
			Ratings: []Rating{{
				Severity: "low",
				Method:   "other",
				Source:   &Source{Name: "deps.dev"},
			}},
		}

		compKey := e.Name + "@" + e.Version
		if ref, ok := compRefs[compKey]; ok {
			vuln.Affects = append(vuln.Affects, Affect{Ref: ref})
		}

		vuln.Properties = append(vuln.Properties,
			Property{Name: "vulnetix:signal-type", Value: "provenance"},
			Property{Name: "vulnetix:source", Value: "deps.dev"},
		)

		vulns = append(vulns, vuln)
	}
	return vulns
}

// outdatedVulns generates low-severity signals for significantly outdated packages.
func outdatedVulns(enrichments []depsdev.PackageEnrichment, compRefs map[string]string) []Vulnerability {
	var vulns []Vulnerability
	for _, e := range enrichments {
		if !e.IsOutdated || e.LatestVersion == "" || e.VersionsBehind < 2 {
			continue
		}

		id := fmt.Sprintf("OUTDATED:%s/%s@%s", strings.ToLower(e.Ecosystem), e.Name, e.Version)
		desc := fmt.Sprintf("Installed %s, latest is %s (%d versions behind)",
			e.Version, e.LatestVersion, e.VersionsBehind)

		vuln := Vulnerability{
			BOMRef:      id,
			ID:          id,
			Description: desc,
			Source: &Source{
				Name: "deps.dev",
				URL:  "https://deps.dev",
			},
			Ratings: []Rating{{
				Severity: "low",
				Method:   "other",
				Source:   &Source{Name: "deps.dev"},
			}},
		}

		compKey := e.Name + "@" + e.Version
		if ref, ok := compRefs[compKey]; ok {
			vuln.Affects = append(vuln.Affects, Affect{Ref: ref})
		}

		vuln.Properties = append(vuln.Properties,
			Property{Name: "vulnetix:signal-type", Value: "outdated"},
			Property{Name: "vulnetix:latest-version", Value: e.LatestVersion},
			Property{Name: "vulnetix:versions-behind", Value: fmt.Sprintf("%d", e.VersionsBehind)},
			Property{Name: "vulnetix:source", Value: "deps.dev"},
		)

		vulns = append(vulns, vuln)
	}
	return vulns
}

// CollectExistingVulnIDs builds a set of vulnerability IDs from existing BOM
// vulnerabilities for deduplication against deps.dev advisories.
func CollectExistingVulnIDs(bomVulns []Vulnerability) map[string]bool {
	ids := make(map[string]bool, len(bomVulns))
	for _, v := range bomVulns {
		if v.ID != "" {
			ids[v.ID] = true
		}
	}
	return ids
}
