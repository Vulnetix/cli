package lsp

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vulnetix/cli/v3/internal/lsp/anchor"
	"github.com/vulnetix/cli/v3/internal/lsp/protocol"
	"github.com/vulnetix/cli/v3/internal/scan"
)

// SourceSCA is the Diagnostic.source for dependency findings.
//
// The exact string matters. The extension routes diagnostics into one
// collection per scanner family by matching this against a fixed list, and
// anything it does not recognise is filed as SAST — so a near miss here does
// not fail loudly, it quietly mislabels every dependency finding.
const SourceSCA = "vulnetix-sca"

// scaDiagnosticData is the SCA half of Diagnostic.data.
//
// It carries what a code action needs to build a fix without repeating the
// lookup: which package, at which version, and what the resolved target is.
type scaDiagnosticData struct {
	Purl       string   `json:"purl"`
	Package    string   `json:"package"`
	Version    string   `json:"version"`
	Ecosystem  string   `json:"ecosystem"`
	CveIDs     []string `json:"cveIds,omitempty"`
	TargetVer  string   `json:"targetVersion,omitempty"`
	IsDirect   bool     `json:"isDirect"`
	Transitive bool     `json:"transitive,omitempty"`
}

// SCADiagnostics builds the dependency diagnostics for one document.
func (e *scaEngine) SCADiagnostics(relPath, text string, m SeverityMapping) []protocol.Diagnostic {
	annotations := e.Annotations(relPath, text)
	out := make([]protocol.Diagnostic, 0, len(annotations))

	for i := range annotations {
		a := &annotations[i]
		if !a.Vulnerable() {
			continue
		}
		if diag, ok := e.scaDiagnostic(a, m); ok {
			out = append(out, diag)
		}
	}
	return out
}

func (e *scaEngine) scaDiagnostic(a *scaAnnotation, m SeverityMapping) (protocol.Diagnostic, bool) {
	vulns := a.AllVulns()
	if len(vulns) == 0 {
		return protocol.Diagnostic{}, false
	}

	counts := countBySeverityLabel(vulns)
	worst := worstSeverity(vulns)
	top := topVuln(vulns)

	diag := protocol.Diagnostic{
		Range:    a.Range,
		Severity: severityToLSP(worst, m),
		Source:   SourceSCA,
		Message:  scaMessage(a, vulns, counts, top),
	}

	if top.CveID != "" {
		diag.Code = top.CveID
		if href := advisoryURL(top.CveID); href != "" {
			diag.CodeDescription = &protocol.CodeDescription{Href: href}
		}
	}

	// An end-of-life package gets the deprecated tag, which editors render with
	// a strikethrough. That is the honest signal: the problem is not a version
	// to bump to, it is that nobody is going to publish one.
	if a.Verdict != nil && a.Verdict.Insight != nil && a.Verdict.Insight.IsEOL {
		diag.Tags = append(diag.Tags, protocol.TagDeprecated)
	}

	diag.RelatedInformation = e.scaRelatedInformation(a)

	target := ""
	if a.Verdict != nil {
		target = e.targetVersionFor(a.Verdict)
	}

	data := DiagnosticData{
		FindingID:        scaFindingID(a),
		Tool:             "sca",
		RuleID:           top.CveID,
		AnchorConfidence: string(a.Confidence),
		FixAvailable:     target != "",
		Suppressible:     true,
		SCA: &scaDiagnosticData{
			Purl:       purlOf(a),
			Package:    a.Pkg.Name,
			Version:    a.Pkg.Version,
			Ecosystem:  a.Pkg.Ecosystem,
			CveIDs:     cveIDs(vulns),
			TargetVer:  target,
			IsDirect:   a.Pkg.IsDirect,
			Transitive: len(a.Introduced) > 0,
		},
	}
	if raw, err := json.Marshal(data); err == nil {
		diag.Data = raw
	}

	return diag, true
}

// scaMessage renders the one-line summary the Problems panel shows.
//
// Shape follows what the finding actually is: the package and version being
// named first is what a reader scans for, the counts say how bad, and the
// leading CVE gives something to search. When the vulnerability is transitive
// the message says so rather than implying the named package is itself
// vulnerable.
func scaMessage(a *scaAnnotation, vulns []scan.EnrichedVuln, counts map[string]int, top scan.EnrichedVuln) string {
	var b strings.Builder

	ownCount := 0
	if a.Verdict != nil {
		ownCount = len(a.Verdict.Vulns)
	}

	fmt.Fprintf(&b, "%s@%s: %s", a.Pkg.Name, a.Pkg.Version, pluralVulns(len(vulns)))

	if split := severitySplit(counts); split != "" {
		fmt.Fprintf(&b, " (%s)", split)
	}

	if ownCount == 0 && len(a.Introduced) > 0 {
		// Nothing wrong with this package; it is the route to something else.
		fmt.Fprintf(&b, " introduced via %s", strings.Join(introducedNames(a.Introduced), ", "))
	} else if len(a.Introduced) > 0 {
		fmt.Fprintf(&b, ", including %s pulled in transitively", strings.Join(introducedNames(a.Introduced), ", "))
	}

	if top.CveID != "" {
		fmt.Fprintf(&b, " — %s", top.CveID)
		if top.InCisaKev {
			b.WriteString(" (CISA KEV)")
		}
	}
	return b.String()
}

// scaRelatedInformation points at the transitive packages rolled up onto this
// line, and at the manifest a finding was declared in when that differs.
func (e *scaEngine) scaRelatedInformation(a *scaAnnotation) []protocol.DiagnosticRelatedInformation {
	if len(a.Introduced) == 0 {
		return nil
	}
	out := make([]protocol.DiagnosticRelatedInformation, 0, len(a.Introduced))
	for _, v := range a.Introduced {
		e.mu.Lock()
		root := e.root
		e.mu.Unlock()
		uri := PathToURI(filepath.Join(root, filepath.FromSlash(v.SourceFile)))
		if uri == "" {
			continue
		}
		out = append(out, protocol.DiagnosticRelatedInformation{
			Location: protocol.Location{
				URI: uri,
				// The precise line inside the other file is not resolved here:
				// it needs that file's text, which the server may not hold. The
				// file itself is the useful part of the link.
				Range: protocol.Range{},
			},
			Message: fmt.Sprintf("%s@%s: %s", v.Name, v.Version, pluralVulns(len(v.Vulns))),
		})
	}
	return out
}

// targetVersionFor resolves the version a quick fix would move to, or empty
// when Safe-Harbour has not answered or had nothing to offer.
func (e *scaEngine) targetVersionFor(v *scaVerdict) string {
	if v == nil || v.Insight == nil {
		return ""
	}
	cfg := e.settings()
	target, decision := resolveFixTarget(v, cfg)
	if decision.Skipped {
		return ""
	}
	return target
}

// ── Rendering helpers ────────────────────────────────────────────────────────

func pluralVulns(n int) string {
	if n == 1 {
		return "1 vulnerability"
	}
	return fmt.Sprintf("%d vulnerabilities", n)
}

// severityOrder is worst-first, which is both the sort order and the render
// order for the count split.
var severityOrder = []string{"critical", "high", "medium", "low", "info"}

func countBySeverityLabel(vulns []scan.EnrichedVuln) map[string]int {
	counts := map[string]int{}
	for _, v := range vulns {
		counts[normaliseSeverity(v.MaxSeverity)]++
	}
	return counts
}

// severitySplit renders "2 critical, 3 high", omitting the tail that carries no
// information: a reader deciding whether to act does not need the low count.
func severitySplit(counts map[string]int) string {
	parts := make([]string, 0, 2)
	for _, label := range severityOrder {
		if n := counts[label]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, label))
		}
		if len(parts) == 2 {
			break
		}
	}
	return strings.Join(parts, ", ")
}

func worstSeverity(vulns []scan.EnrichedVuln) string {
	best := "info"
	bestRank := severityRank(best)
	for _, v := range vulns {
		if r := severityRank(v.MaxSeverity); r < bestRank {
			bestRank = r
			best = normaliseSeverity(v.MaxSeverity)
		}
	}
	return best
}

// severityRank orders severities worst-first, so a lower rank is more severe.
func severityRank(severity string) int {
	target := normaliseSeverity(severity)
	for i, label := range severityOrder {
		if label == target {
			return i
		}
	}
	return len(severityOrder)
}

func normaliseSeverity(severity string) string {
	s := strings.ToLower(strings.TrimSpace(severity))
	switch s {
	case "critical", "high", "medium", "low":
		return s
	case "moderate":
		return "medium"
	case "none", "":
		return "info"
	}
	return s
}

// topVuln picks the one vulnerability to name in a one-line message: most
// severe, then known-exploited, then highest exploit count, then newest
// identifier.
//
// The last tiebreak is not arbitrary. Among equally severe advisories the more
// recent one is the more useful thing to name — it is what a reader is likely
// to have heard of and what a search will find current information about — and
// ordering by identifier keeps the choice stable across scans.
func topVuln(vulns []scan.EnrichedVuln) scan.EnrichedVuln {
	if len(vulns) == 0 {
		return scan.EnrichedVuln{}
	}
	sorted := make([]scan.EnrichedVuln, len(vulns))
	copy(sorted, vulns)

	sort.SliceStable(sorted, func(i, j int) bool {
		ri, rj := severityRank(sorted[i].MaxSeverity), severityRank(sorted[j].MaxSeverity)
		if ri != rj {
			return ri < rj
		}
		ki, kj := sorted[i].InCisaKev, sorted[j].InCisaKev
		if ki != kj {
			return ki
		}
		// Prefer a CVE over a database-specific identifier, ahead of the exploit
		// count rather than after it. The same advisory routinely arrives under
		// both a CVE and a GHSA with different per-source exploit tallies, so
		// ranking on the tally first picks a name by an accident of which
		// database recorded more. The CVE is the name that appears in advisories,
		// tickets and news, so it is the one worth showing.
		ci, cj := isCVE(sorted[i].CveID), isCVE(sorted[j].CveID)
		if ci != cj {
			return ci
		}
		if sorted[i].ExploitCount != sorted[j].ExploitCount {
			return sorted[i].ExploitCount > sorted[j].ExploitCount
		}
		return sorted[i].CveID > sorted[j].CveID
	})
	return sorted[0]
}

func cveIDs(vulns []scan.EnrichedVuln) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(vulns))
	for _, v := range vulns {
		if v.CveID == "" || seen[v.CveID] {
			continue
		}
		seen[v.CveID] = true
		out = append(out, v.CveID)
	}
	sort.Strings(out)
	return out
}

func introducedNames(verdicts []*scaVerdict) []string {
	out := make([]string, 0, len(verdicts))
	for _, v := range verdicts {
		out = append(out, v.Name+"@"+v.Version)
	}
	return out
}

// advisoryURL links an identifier to its canonical public page.
//
// Only formats with a stable, known URL are linked. Guessing one for an
// unrecognised identifier produces a 404, which is worse than no link.
func advisoryURL(id string) string {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return "https://nvd.nist.gov/vuln/detail/" + id
	case strings.HasPrefix(id, "GHSA-"):
		return "https://github.com/advisories/" + id
	}
	return ""
}

// scaFindingID is the stable identity of a dependency finding, matching the
// `tool:vuln:purl` shape the protocol's Finding type documents. Stability is
// what lets a client keep selection and expansion state across a rescan.
func scaFindingID(a *scaAnnotation) string {
	top := topVuln(a.AllVulns())
	return "sca:" + top.CveID + ":" + purlOf(a)
}

func purlOf(a *scaAnnotation) string {
	if a.Verdict != nil {
		return a.Verdict.Purl
	}
	return ""
}

// scaConfidenceOf exposes the anchor confidence as the protocol string.
func scaConfidenceOf(a *scaAnnotation) string {
	if a.Confidence == "" {
		return string(anchor.ConfidenceToken)
	}
	return string(a.Confidence)
}

// isCVE reports whether an identifier is a CVE rather than a database-specific
// alias such as a GHSA. Used only to break ties between equally severe
// advisories, where the CVE is the more recognisable name.
func isCVE(id string) bool {
	return strings.HasPrefix(id, "CVE-")
}
