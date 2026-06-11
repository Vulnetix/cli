package scan

// SynthesiseFromCDX turns the CycloneDX 1.6 document returned by /v2/cli.sca
// into the same data structures the legacy LookupVulns + EnrichVulns pair
// produces, so the rest of cmd/scan.go (BOM build, license analysis, quality
// gate, memory writes, pretty printing) runs unchanged on the API-served path.
//
// Mapping strategy:
//   - upstream `components[]` carries purls — match each component's purl back
//     to a local ScopedPackage. The cli.sca request was built from
//     allPackages, so every component should have at least one matching
//     ScopedPackage entry. Multiple ScopedPackage entries with the same purl
//     (same package introduced by N manifests) all share one component; we
//     emit one VulnFinding *per ScopedPackage* so PathCount sums correctly
//     downstream.
//   - upstream `vulnerabilities[].affects[].ref` points at the upstream
//     component's bom-ref. We resolve ref → purl → ScopedPackage[] and emit
//     one finding per (vuln, scoped-package) pair.
//   - ratings populate Score/MetricType/CVSSScore/EPSSScore. The first non-zero
//     CVSS rating wins for the per-finding `Score`; severity is taken from
//     the same rating.
//   - upstream `properties` (vulnetix:inCisaKev, vulnetix:exploitCount,
//     vulnetix:isMalicious, vulnetix:confirmed) stamp the boolean / count
//     fields. Unknown properties are ignored.

import (
	"strconv"
	"strings"

	"github.com/vulnetix/cli/v3/internal/versions"
)

// epssSeverity tiers EPSS probability into the legacy severity ladder.
func epssSeverity(score float64) string {
	switch {
	case score >= 0.7:
		return "critical"
	case score >= 0.4:
		return "high"
	case score >= 0.1:
		return "medium"
	case score > 0:
		return "low"
	default:
		return ""
	}
}

// cessSeverity tiers Coalition ESS into the legacy severity ladder.
func cessSeverity(score float64) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "medium"
	case score > 0:
		return "low"
	default:
		return ""
	}
}

// ssvcSeverity maps an SSVC decision to the severity ladder used elsewhere.
func ssvcSeverity(decision string) string {
	switch decision {
	case "Act":
		return "critical"
	case "Attend":
		return "high"
	case "Track*":
		return "medium"
	case "Track":
		return "low"
	default:
		return ""
	}
}

// maxSeverity returns the highest severity across the supplied per-source
// severity strings. Matches the legacy precedence: critical > high > medium > low.
func maxSeverity(sevs ...string) string {
	rank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
	best := ""
	bestR := 0
	for _, s := range sevs {
		if r := rank[strings.ToLower(s)]; r > bestR {
			best = strings.ToLower(s)
			bestR = r
		}
	}
	return best
}

// SynthesiseFromCDX converts an upstream CycloneDX 1.6 document into the
// internal finding shapes. Returns nil slices when the document is empty or
// malformed — callers should treat a nil result as "fall back to legacy".
//
// packages and purls are parallel arrays — `purls[i]` is the PURL the caller
// computed (via cdx.BuildLocalPurl) for `packages[i]`. Empty purl entries are
// silently ignored. Keeping the purl derivation outside this package avoids a
// scan→cdx import cycle.
func SynthesiseFromCDX(cdxDoc map[string]any, packages []ScopedPackage, purls []string) (findings []VulnFinding, enriched []EnrichedVuln, stats *LookupStats) {
	if len(cdxDoc) == 0 {
		return nil, nil, nil
	}

	// Group ScopedPackage entries by their derived purl. Multiple manifests
	// can introduce the same dep, so the value is a slice.
	pkgsByPurl := make(map[string][]ScopedPackage, len(packages))
	for i, p := range packages {
		if i >= len(purls) || purls[i] == "" {
			continue
		}
		pkgsByPurl[purls[i]] = append(pkgsByPurl[purls[i]], p)
	}

	// Map upstream bom-ref → purl, so vuln.affects[].ref can be resolved.
	refToPurl := make(map[string]string)
	if comps, ok := cdxDoc["components"].([]any); ok {
		for _, c := range comps {
			obj, ok := c.(map[string]any)
			if !ok {
				continue
			}
			ref, _ := obj["bom-ref"].(string)
			purl, _ := obj["purl"].(string)
			if ref != "" && purl != "" {
				refToPurl[ref] = purl
			}
			// Some upstream components use the purl itself as the bom-ref.
			if ref == "" && purl != "" {
				refToPurl[purl] = purl
			}
		}
	}

	vulns, _ := cdxDoc["vulnerabilities"].([]any)
	if len(vulns) == 0 {
		// Empty findings is a valid response — return an empty (non-nil)
		// slice so the caller knows the API was reached and there is
		// genuinely nothing to report.
		return []VulnFinding{}, []EnrichedVuln{}, &LookupStats{Total: len(packages), Succeeded: len(packages)}
	}

	for _, v := range vulns {
		obj, ok := v.(map[string]any)
		if !ok {
			continue
		}
		cveID, _ := obj["id"].(string)
		if cveID == "" {
			continue
		}

		// Resolve every affected component back to one or more ScopedPackage entries.
		affectedPkgs := resolveAffectedPackages(obj, refToPurl, pkgsByPurl)
		if len(affectedPkgs) == 0 {
			// Vuln references a component we didn't ask about — keep it as a
			// floating finding so quality gates and pretty-print still see it.
			affectedPkgs = []ScopedPackage{{}}
		}

		score, metric, severity, cvssScore, epssScore, vector := extractRatings(obj)
		props := extractVulnetixProps(obj)
		source := extractSourceName(obj)

		for _, pkg := range affectedPkgs {
			f := VulnFinding{
				CveID:          cveID,
				PackageName:    pkg.Name,
				PackageVer:     pkg.Version,
				Ecosystem:      pkg.Ecosystem,
				Scope:          pkg.Scope,
				Severity:       severity,
				Score:          score,
				MetricType:     metric,
				VectorString:   vector,
				SourceFile:     pkg.SourceFile,
				Source:         source,
				InCisaKev:      props.inCisaKev,
				InVulnCheckKev: props.inVulnCheckKev,
				InEuKev:        props.inEuKev,
				ExploitCount:   props.exploitCount,
			}
			findings = append(findings, f)

			ev := EnrichedVuln{
				VulnFinding:     f,
				Confirmed:       props.confirmed,
				IsMalicious:     props.isMalicious,
				CVSSScore:       cvssScore,
				EPSSScore:       epssScore,
				EPSSPercentile:  props.epssPercentile,
				CoalitionESS:    props.cessScore,
				CVSSSeverity:    severity,
				EPSSSeverity:    epssSeverity(epssScore),
				CESSeverity:     cessSeverity(props.cessScore),
				SSVCDecision:    props.ssvcDecision,
				SSVCSeverity:    ssvcSeverity(props.ssvcDecision),
				FixAvailability: props.fixAvailability,
				MaxSeverity:     maxSeverity(severity, epssSeverity(epssScore), cessSeverity(props.cessScore), ssvcSeverity(props.ssvcDecision)),
				MatchMethod:     "name+version",
				AffectedRange:   props.affectedRange,
				VersionStatus:   props.versionStatus,
			}
			if ev.VersionStatus == "" {
				// Older servers don't emit vulnetix:versionStatus — derive
				// from the multi-source confirmation flag.
				if props.confirmed {
					ev.VersionStatus = string(versions.StatusAffected)
				} else {
					ev.VersionStatus = string(versions.StatusUnknown)
				}
			}
			if props.exploitCount > 0 {
				ev.ExploitIntel = &ExploitSummary{
					ExploitCount:    props.exploitCount,
					Sources:         props.exploitSources,
					HasWeaponized:   props.hasWeaponized,
					HighestMaturity: props.highestMaturity,
				}
			}
			if props.fixVersion != "" || len(props.remediationActions) > 0 || props.fixAvailability != "" {
				ev.Remediation = &RemediationInfo{
					FixAvailability: props.fixAvailability,
					FixVersion:      props.fixVersion,
					Actions:         props.remediationActions,
				}
			}
			// Always seed the symbol set with the package name itself.
			// When the server has no programRoutines / programFiles for a
			// CVE — common for Go modules — the import path is the only
			// thing reliably present in user source. The grep matcher's
			// quality threshold accepts path-shaped names (golang.org/x/…)
			// so this fires for any project that imports the affected dep.
			ev.AffectedSymbols = &AffectedSymbols{
				Routines: props.affectedRoutines,
				Files:    props.affectedFiles,
				Modules:  appendIfMissing(props.affectedModules, pkg.Name),
			}
			enriched = append(enriched, ev)
		}
	}

	stats = &LookupStats{
		Total:     len(packages),
		Succeeded: len(packages),
	}
	return findings, enriched, stats
}

// resolveAffectedPackages extracts the affected component refs from one
// upstream vulnerability and resolves each one to the ScopedPackage entries
// that share its purl. Used as a lookup helper, not a public API.
func resolveAffectedPackages(vuln map[string]any, refToPurl map[string]string, pkgsByPurl map[string][]ScopedPackage) []ScopedPackage {
	affects, ok := vuln["affects"].([]any)
	if !ok {
		return nil
	}
	out := make([]ScopedPackage, 0, len(affects))
	seen := make(map[string]bool)
	for _, a := range affects {
		aObj, ok := a.(map[string]any)
		if !ok {
			continue
		}
		ref, _ := aObj["ref"].(string)
		if ref == "" {
			continue
		}
		purl := refToPurl[ref]
		if purl == "" {
			purl = ref // fall back: ref might be the purl itself
		}
		for _, p := range pkgsByPurl[purl] {
			key := p.Name + "@" + p.Version + "@" + p.SourceFile
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, p)
		}
	}
	return out
}

// extractRatings returns the most-informative rating from upstream:
//   - score / metric / vector come from the first non-zero CVSS rating
//   - cvssScore + epssScore are tracked separately so the EnrichedVuln gets
//     both populated even when only one is present
//   - severity is whichever rating supplied a severity label, preferring CVSS
func extractRatings(vuln map[string]any) (score float64, metric, severity string, cvssScore, epssScore float64, vector string) {
	ratings, ok := vuln["ratings"].([]any)
	if !ok {
		return
	}
	for _, r := range ratings {
		rObj, ok := r.(map[string]any)
		if !ok {
			continue
		}
		rscore, _ := rObj["score"].(float64)
		rmethod, _ := rObj["method"].(string)
		rseverity, _ := rObj["severity"].(string)
		rvector, _ := rObj["vector"].(string)

		// Source.name tells us cvss vs epss for non-method-aware backends.
		sourceName := ""
		if src, ok := rObj["source"].(map[string]any); ok {
			sourceName, _ = src["name"].(string)
		}

		switch {
		case strings.HasPrefix(rmethod, "CVSS"), strings.EqualFold(sourceName, "cvss"):
			if cvssScore == 0 {
				cvssScore = rscore
			}
			if score == 0 {
				score = rscore
				metric = rmethod
				vector = rvector
			}
			if severity == "" {
				severity = rseverity
			}
		case strings.EqualFold(sourceName, "epss"), strings.EqualFold(rmethod, "epss"):
			if epssScore == 0 {
				epssScore = rscore
			}
		default:
			// Unknown rating — still take it as a fallback score if nothing
			// else has populated it yet.
			if score == 0 {
				score = rscore
				metric = rmethod
				vector = rvector
			}
			if severity == "" {
				severity = rseverity
			}
		}
	}
	return
}

// extractSourceName returns the upstream source.name field. Defaults to empty
// (the legacy convention for "vulnetix" sourcing).
func extractSourceName(vuln map[string]any) string {
	src, ok := vuln["source"].(map[string]any)
	if !ok {
		return ""
	}
	name, _ := src["name"].(string)
	return name
}

// vulnetixProps collects the flat boolean/count fields the server stamps on
// each CDX vuln via `properties[]`. New names land here without touching
// callers — anything unknown is silently ignored.
type vulnetixProps struct {
	inCisaKev          bool
	inVulnCheckKev     bool
	inEuKev            bool
	isMalicious        bool
	confirmed          bool
	versionStatus      string
	exploitCount       int
	exploitSources     []string
	hasWeaponized      bool
	highestMaturity    string
	affectedRange      string
	epssPercentile     float64
	cessScore          float64
	fixAvailability    string
	fixVersion         string
	remediationActions []string
	ssvcDecision       string
	affectedRoutines   []string
	affectedFiles      []string
	affectedModules    []string
}

func extractVulnetixProps(vuln map[string]any) vulnetixProps {
	var p vulnetixProps
	props, ok := vuln["properties"].([]any)
	if !ok {
		return p
	}
	for _, raw := range props {
		obj, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name, _ := obj["name"].(string)
		val, _ := obj["value"].(string)
		switch name {
		case "vulnetix:inCisaKev":
			p.inCisaKev = val == "true"
		case "vulnetix:inVulnCheckKev":
			p.inVulnCheckKev = val == "true"
		case "vulnetix:inEuKev":
			p.inEuKev = val == "true"
		case "vulnetix:isMalicious":
			p.isMalicious = val == "true"
		case "vulnetix:confirmed":
			p.confirmed = val == "true"
		case "vulnetix:versionStatus":
			p.versionStatus = val
		case "vulnetix:exploitCount":
			if n, err := parseInt(val); err == nil {
				p.exploitCount = n
			}
		case "vulnetix:affectedRange":
			p.affectedRange = val
		case "vulnetix:epssPercentile":
			if f, err := strconv.ParseFloat(val, 64); err == nil {
				p.epssPercentile = f
			}
		case "vulnetix:cess":
			if f, err := strconv.ParseFloat(val, 64); err == nil {
				p.cessScore = f
			}
		case "vulnetix:fixAvailability":
			p.fixAvailability = val
		case "vulnetix:fixVersion":
			p.fixVersion = val
		case "vulnetix:ssvc":
			p.ssvcDecision = val
		case "vulnetix:exploitSources":
			if val != "" {
				p.exploitSources = strings.Split(val, ",")
			}
		case "vulnetix:hasWeaponized":
			p.hasWeaponized = val == "true"
		case "vulnetix:highestMaturity":
			p.highestMaturity = val
		case "vulnetix:remediationActions":
			if val != "" {
				// Server joins with " | " — split symmetrically.
				p.remediationActions = strings.Split(val, " | ")
			}
		case "vulnetix:affectedRoutines":
			if val != "" {
				p.affectedRoutines = strings.Split(val, "|")
			}
		case "vulnetix:affectedFiles":
			if val != "" {
				p.affectedFiles = strings.Split(val, "|")
			}
		case "vulnetix:affectedModules":
			if val != "" {
				p.affectedModules = strings.Split(val, "|")
			}
		}
	}
	return p
}

// appendIfMissing returns s with v appended when v is non-empty and not
// already present. Used to seed the package name as a fallback symbol.
func appendIfMissing(s []string, v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return s
	}
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func parseInt(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, nil
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errBadInt
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}

type sentinelErr string

func (e sentinelErr) Error() string { return string(e) }

const errBadInt sentinelErr = "not an integer"
