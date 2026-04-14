package cdx

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vulnetix/cli/internal/scan"
)

// LocalScanResult holds the parsed packages and found vulnerabilities for one manifest file.
type LocalScanResult struct {
	File          scan.DetectedFile
	Packages      []scan.ScopedPackage
	Vulns         []scan.VulnFinding
	EnrichedVulns []scan.EnrichedVuln // populated after enrichment; used for full ratings
}

// vulnDedupKey is used to deduplicate vulnerabilities by (CVE ID, package ref).
type vulnDedupKey struct {
	CveID   string
	PkgName string
}

// BuildFromLocalScan creates a CycloneDX BOM from locally-parsed manifest data and VDB findings.
//
// Components are deduplicated by (name, version). Each component carries its ecosystem scope
// (required = production/runtime, optional = dev/test/peer/provided/system) and a PURL.
// Vulnerabilities include CVSS ratings and links back to affected components.
//
// When scanCtx is non-nil the BOM metadata is enriched with git-repository context
// (branch, commit, dirty state, worktree, VCS remotes, recent authors) and host
// environment context (hostname, shell, OS, arch, user).
func BuildFromLocalScan(results []LocalScanResult, specVersion string, scanCtx *ScanContext, seed *BOM) *BOM {
	// Use 1.7 by default, but if a seed BOM is provided with a different version,
	// keep the seed's version to preserve compatibility.
	if specVersion == "" {
		if seed != nil && seed.SpecVersion != "" {
			specVersion = seed.SpecVersion
		} else {
			specVersion = "1.7"
		}
	}

	toolVersion := "cli"
	if scanCtx != nil && scanCtx.ToolVersion != "" {
		toolVersion = scanCtx.ToolVersion
	}

	bom := &BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  specVersion,
		SerialNumber: "urn:uuid:" + uuid.New().String(),
		Version:      1,
		Metadata: &Metadata{
			Timestamp:  time.Now().UTC().Format(time.RFC3339),
			Lifecycles: []Lifecycle{{Phase: "build"}},
			Tools: &Tools{
				Components: []Component{
					{Type: "application", Name: "vulnetix-sca", Version: toolVersion},
				},
			},
		},
	}

	if scanCtx != nil {
		populateMetadataFromContext(bom.Metadata, scanCtx)
	}

	// Map "name@version" → bom-ref for cross-referencing vulnerabilities.
	compRefs := make(map[string]string)

	// ── Merge seed BOM if versions match ─────────────────────────────────────
	seedCompatible := seed != nil && seed.SpecVersion == specVersion

	if seedCompatible {
		// Pre-populate components.
		for _, c := range seed.Components {
			compKey := c.Name + "@" + c.Version
			if _, ok := compRefs[compKey]; !ok {
				compRefs[compKey] = c.BOMRef
				bom.Components = append(bom.Components, c)
			}
		}

		// Pre-populate vulnerabilities (deduped by id+affect).
		seenSeedVulns := map[vulnDedupKey]bool{}
		for _, sv := range seed.Vulnerabilities {
			if len(sv.Affects) == 0 {
				continue
			}
			for _, a := range sv.Affects {
				dk := vulnDedupKey{sv.ID, a.Ref}
				if !seenSeedVulns[dk] {
					seenSeedVulns[dk] = true
					bom.Vulnerabilities = append(bom.Vulnerabilities, sv)
				}
			}
		}

		// Preserve serial number and tools from seed.
		bom.SerialNumber = seed.SerialNumber
		bom.Version = seed.Version
		if seed.Metadata != nil {
			bom.Metadata.Tools = seed.Metadata.Tools
			if seed.Metadata.Component != nil {
				bom.Metadata.Component = seed.Metadata.Component
			}
		}
	}

	for _, result := range results {
		for _, pkg := range result.Packages {
			compKey := pkg.Name + "@" + pkg.Version
			if _, exists := compRefs[compKey]; exists {
				continue // deduplicate across files
			}

			purl := buildLocalPurl(pkg.Name, pkg.Version, pkg.Ecosystem)
			bomRef := purl
			if bomRef == "" {
				bomRef = fmt.Sprintf("pkg:%s/%s@%s", pkg.Ecosystem, pkg.Name, pkg.Version)
			}
			compRefs[compKey] = bomRef

			comp := Component{
				Type:    "library",
				BOMRef:  bomRef,
				Name:    pkg.Name,
				Version: pkg.Version,
				Scope:   mapLocalScopeToCDX(pkg.Scope),
				Purl:    purl,
				Properties: []Property{
					{Name: "vulnetix:scope", Value: pkg.Scope},
					{Name: "vulnetix:ecosystem", Value: pkg.Ecosystem},
				},
			}
			if pkg.SourceFile != "" {
				comp.Properties = append(comp.Properties, Property{
					Name:  "vulnetix:source-file",
					Value: pkg.SourceFile,
				})
			}
			bom.Components = append(bom.Components, comp)
		}
	}

	// Deduplicate vulnerabilities by (cveId, packageName) then emit.
	seenVulns := make(map[vulnDedupKey]bool)

	// Build an enriched-vuln index keyed by (cveId, packageName) so we can
	// attach full scoring data when available.
	type enrichedKey struct {
		CveID   string
		PkgName string
	}
	enrichedIndex := make(map[enrichedKey]*scan.EnrichedVuln)
	for _, result := range results {
		for i := range result.EnrichedVulns {
			ev := &result.EnrichedVulns[i]
			k := enrichedKey{ev.CveID, ev.PackageName}
			if _, exists := enrichedIndex[k]; !exists {
				enrichedIndex[k] = ev
			}
		}
	}

	for _, result := range results {
		for _, v := range result.Vulns {
			dk := vulnDedupKey{v.CveID, v.PackageName}
			if seenVulns[dk] {
				continue
			}
			seenVulns[dk] = true

			vuln := Vulnerability{
				BOMRef: v.CveID,
				ID:     v.CveID,
				Source: vulnSourceForFind(v),
			}

			// Look up enriched data for this vuln.
			ev := enrichedIndex[enrichedKey{v.CveID, v.PackageName}]

			if ev != nil {
				// Full enriched ratings: CVSS, EPSS, Coalition ESS, SSVC.
				if ev.CVSSScore > 0 {
					metricType := v.MetricType
					if metricType == "" {
						metricType = "cvssv3.1"
					}
					method := scoreTypeToMethod[strings.ToLower(metricType)]
					if method == "" {
						method = "other"
					}
					vuln.Ratings = append(vuln.Ratings, Rating{
						Score:    ev.CVSSScore,
						Severity: strings.ToLower(ev.CVSSSeverity),
						Method:   method,
						Source:   &Source{Name: "NVD"},
					})
				} else if v.Score > 0 {
					// Fall back to raw score when enriched CVSS isn't available.
					method := scoreTypeToMethod[strings.ToLower(v.MetricType)]
					if method == "" {
						method = "other"
					}
					vuln.Ratings = append(vuln.Ratings, Rating{
						Score:    v.Score,
						Severity: strings.ToLower(v.Severity),
						Method:   method,
					})
				}

				if ev.EPSSScore > 0 {
					vuln.Ratings = append(vuln.Ratings, Rating{
						Score:    ev.EPSSScore,
						Severity: strings.ToLower(ev.EPSSSeverity),
						Method:   "other",
						Source:   &Source{Name: "EPSS"},
					})
				}

				if ev.CoalitionESS > 0 {
					vuln.Ratings = append(vuln.Ratings, Rating{
						Score:    ev.CoalitionESS,
						Severity: strings.ToLower(ev.CESSeverity),
						Method:   "other",
						Source:   &Source{Name: "Coalition ESS"},
					})
				}

				if ev.SSVCDecision != "" {
					vuln.Ratings = append(vuln.Ratings, Rating{
						Score:    float64(scan.SeverityLevel(ev.SSVCSeverity)),
						Severity: strings.ToLower(ev.SSVCSeverity),
						Method:   "other",
						Source:   &Source{Name: "SSVC"},
					})
				}

				// Properties: SSVC decision, max-severity, KEV flags.
				if ev.SSVCDecision != "" {
					vuln.Properties = append(vuln.Properties, Property{
						Name:  "vulnetix:ssvc-decision",
						Value: ev.SSVCDecision,
					})
				}
				if ev.MaxSeverity != "" {
					vuln.Properties = append(vuln.Properties, Property{
						Name:  "vulnetix:max-severity",
						Value: strings.ToLower(ev.MaxSeverity),
					})
				}
				if ev.AffectedRange != "" {
					vuln.Properties = append(vuln.Properties, Property{
						Name:  "vulnetix:affected-range",
						Value: ev.AffectedRange,
					})
				}
				if ev.FixAvailability != "" {
					vuln.Properties = append(vuln.Properties, Property{
						Name:  "vulnetix:fix-availability",
						Value: ev.FixAvailability,
					})
				}
				if ev.Remediation != nil && ev.Remediation.FixVersion != "" {
					vuln.Properties = append(vuln.Properties, Property{
						Name:  "vulnetix:fix-version",
						Value: ev.Remediation.FixVersion,
					})
				}
				if ev.IsMalicious {
					vuln.Analysis = &Analysis{State: "exploitable"}
					vuln.Properties = append(vuln.Properties, Property{
						Name:  "vulnetix:malware",
						Value: "true",
					})
				}
			} else {
				// No enrichment — emit the single raw CVSS-style rating.
				if v.Score > 0 {
					method := scoreTypeToMethod[strings.ToLower(v.MetricType)]
					if method == "" {
						method = "other"
					}
					vuln.Ratings = append(vuln.Ratings, Rating{
						Score:    v.Score,
						Severity: strings.ToLower(v.Severity),
						Method:   method,
					})
				}
			}

			// Link to affected component.
			compKey := v.PackageName + "@" + v.PackageVer
			if bomRef, ok := compRefs[compKey]; ok {
				vuln.Affects = append(vuln.Affects, Affect{Ref: bomRef})
			}

			if v.SourceFile != "" {
				vuln.Properties = append(vuln.Properties, Property{
					Name:  "vulnetix:source-file",
					Value: v.SourceFile,
				})
			}
			if v.Scope != "" {
				vuln.Properties = append(vuln.Properties, Property{
					Name:  "vulnetix:scope",
					Value: v.Scope,
				})
			}
			if v.InCisaKev {
				vuln.Properties = append(vuln.Properties, Property{
					Name:  "vulnetix:in-cisa-kev",
					Value: "true",
				})
			}
			if v.InVulnCheckKev {
				vuln.Properties = append(vuln.Properties, Property{
					Name:  "vulnetix:in-vulncheck-kev",
					Value: "true",
				})
			}
			if v.InEuKev {
				vuln.Properties = append(vuln.Properties, Property{
					Name:  "vulnetix:in-eu-kev",
					Value: "true",
				})
			}

			bom.Vulnerabilities = append(bom.Vulnerabilities, vuln)
		}
	}

	return bom
}

// mapLocalScopeToCDX maps native package manager scope labels to CycloneDX scope values.
// CycloneDX only supports "required" and "optional".
func mapLocalScopeToCDX(scope string) string {
	switch scope {
	case scan.ScopeProduction, scan.ScopeRuntime:
		return "required"
	case scan.ScopeDevelopment, scan.ScopeTest, scan.ScopePeer,
		scan.ScopeOptional, scan.ScopeProvided, scan.ScopeSystem:
		return "optional"
	default:
		return "required"
	}
}

// buildLocalPurl builds a Package URL string for a dependency.
func buildLocalPurl(name, version, ecosystem string) string {
	purlType := localEcosystemToPurlType(ecosystem)
	if purlType == "" {
		return ""
	}

	// npm scoped packages: @scope/name → pkg:npm/scope/name
	if purlType == "npm" && strings.HasPrefix(name, "@") {
		parts := strings.SplitN(name[1:], "/", 2)
		if len(parts) == 2 {
			if version != "" {
				return fmt.Sprintf("pkg:npm/%s/%s@%s",
					url.PathEscape(parts[0]), parts[1], url.PathEscape(version))
			}
			return fmt.Sprintf("pkg:npm/%s/%s", url.PathEscape(parts[0]), parts[1])
		}
	}

	// Maven group:artifact → pkg:maven/group/artifact
	if purlType == "maven" && strings.Contains(name, ":") {
		parts := strings.SplitN(name, ":", 2)
		if len(parts) == 2 {
			if version != "" {
				return fmt.Sprintf("pkg:maven/%s/%s@%s",
					url.PathEscape(parts[0]), url.PathEscape(parts[1]), url.PathEscape(version))
			}
			return fmt.Sprintf("pkg:maven/%s/%s",
				url.PathEscape(parts[0]), url.PathEscape(parts[1]))
		}
	}

	if version != "" {
		return fmt.Sprintf("pkg:%s/%s@%s", purlType, url.PathEscape(name), url.PathEscape(version))
	}
	return fmt.Sprintf("pkg:%s/%s", purlType, url.PathEscape(name))
}

func localEcosystemToPurlType(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return "npm"
	case "pypi":
		return "pypi"
	case "golang", "go":
		return "golang"
	case "cargo", "rust":
		return "cargo"
	case "gem", "rubygems":
		return "gem"
	case "maven", "java":
		return "maven"
	case "composer", "php":
		return "composer"
	case "nuget":
		return "nuget"
	case "pub", "dart":
		return "pub"
	case "hex", "elixir":
		return "hex"
	case "swift":
		return "swift"
	default:
		return ecosystem
	}
}

// PopulateLicenses sets the Licenses field on BOM components using a license map.
// The map key is "name@version" → SPDX license ID or expression.
func PopulateLicenses(bom *BOM, licenseMap map[string]string) {
	if bom == nil || len(licenseMap) == 0 {
		return
	}
	for i := range bom.Components {
		c := &bom.Components[i]
		compKey := c.Name + "@" + c.Version
		spdxID, ok := licenseMap[compKey]
		if !ok || spdxID == "" || spdxID == "UNKNOWN" {
			continue
		}
		// If expression contains OR/AND, use expression field; else use license.id.
		upper := strings.ToUpper(spdxID)
		if strings.Contains(upper, " OR ") || strings.Contains(upper, " AND ") {
			c.Licenses = []LicenseChoice{{Expression: spdxID}}
		} else {
			c.Licenses = []LicenseChoice{{License: &LicenseData{ID: spdxID}}}
		}
	}
}

// BuildDependencies creates the CycloneDX dependencies array from ManifestGroup edges.
// compRefs maps "name@version" → bom-ref for cross-referencing.
func BuildDependencies(groups []scan.ManifestGroup, compRefs map[string]string) []CDXDependency {
	// Build name → bom-ref index (without version, since edges use bare names).
	nameToRef := map[string]string{}
	for key, ref := range compRefs {
		// key is "name@version"; extract name.
		if idx := strings.LastIndex(key, "@"); idx > 0 {
			name := key[:idx]
			if _, exists := nameToRef[name]; !exists {
				nameToRef[name] = ref
			}
		}
	}

	seen := map[string]bool{}
	var deps []CDXDependency

	for _, mg := range groups {
		if mg.Graph == nil || mg.Graph.Edges == nil {
			continue
		}
		for parent, children := range mg.Graph.Edges {
			parentRef, ok := nameToRef[parent]
			if !ok {
				continue
			}
			if seen[parentRef] {
				continue
			}
			seen[parentRef] = true

			var childRefs []string
			for _, child := range children {
				if childRef, ok := nameToRef[child]; ok {
					childRefs = append(childRefs, childRef)
				}
			}
			deps = append(deps, CDXDependency{
				Ref:          parentRef,
				Dependencies: childRefs,
			})
		}
	}

	return deps
}

// ExportCompRefs returns the component reference map built during BuildFromLocalScan.
// This is a helper to expose compRefs for dependency tree building without changing
// BuildFromLocalScan's signature.
func ExportCompRefs(bom *BOM) map[string]string {
	refs := make(map[string]string, len(bom.Components))
	for _, c := range bom.Components {
		refs[c.Name+"@"+c.Version] = c.BOMRef
	}
	return refs
}
