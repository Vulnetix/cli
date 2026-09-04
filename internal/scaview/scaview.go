// Package scaview renders one dependency's security picture as text.
//
// It exists so the editor, the terminal and a coding agent cannot tell
// different stories about the same package. The language server builds a
// Subject from its workspace engine; the agent hook builds one from a single
// lookup; both call the same Card and Headline. A wording change lands in every
// surface at once, and a difference between them becomes impossible rather than
// merely unlikely.
//
// Everything here is pure: no network, no settings lookup, no engine state. The
// caller resolves what it knows and hands over the answer, including the
// distinction between "asked and found nothing" and "did not ask" — see Fix and
// ExploitsGated, which exist for exactly that.
package scaview

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vulnetix/cli/v3/internal/scan"
)

// maxCardVulns caps the vulnerability list in a card. A dependency with forty
// advisories produces a card taller than the editor window, and the ones past
// the top few are not what decides whether to act.
const maxCardVulns = 5

// Pkg identifies the dependency being described.
type Pkg struct {
	Name      string
	Version   string
	Ecosystem string
}

// Label renders the package the way a reader would write it.
//
// The version is omitted when there is not one, rather than rendered as a bare
// separator. An agent asking about a package it has not pinned yet produces
// exactly that case, and "left-pad@" reads as a truncation rather than as the
// absence of a pin.
func (p Pkg) Label() string {
	if strings.TrimSpace(p.Version) == "" {
		return p.Name
	}
	return p.Name + "@" + p.Version
}

// FixState distinguishes the four ways a fix recommendation can be absent, all
// of which render as nothing at all if collapsed into one.
type FixState int

const (
	// FixNotApplicable means the package is clean, so there is nothing to fix.
	FixNotApplicable FixState = iota
	// FixPending means the Safe-Harbour lookup has not answered yet.
	FixPending
	// FixGated means the server withheld ranked versions on this plan. Reporting
	// this as FixNone would tell someone no fix exists when one may well.
	FixGated
	// FixNone means the lookup ran and there is genuinely no usable target.
	FixNone
	// FixAvailable means Target holds a version worth bumping to.
	FixAvailable
)

// Fix is the resolved upgrade recommendation.
type Fix struct {
	State FixState
	// Target is the version to bump to, set only when State is FixAvailable.
	Target string
	// Reason explains a FixNone, or annotates a FixAvailable when the server
	// supplied a rationale.
	Reason string
}

// Insight carries the flags that are not vulnerabilities but change what the
// right action is.
type Insight struct {
	Malicious bool
	EOL       bool
	// EOLFrom is the date support ended, when known.
	EOLFrom string
}

// Subject is everything the renderers need about one dependency.
type Subject struct {
	Pkg Pkg

	// Vulns is every advisory attributed to this line, including those rolled up
	// from transitive packages.
	Vulns []scan.EnrichedVuln
	// OwnVulns counts the advisories against this package itself. When it is
	// zero and Introduced is not, the package is the route to a problem rather
	// than the problem, and the text says so.
	OwnVulns int
	// Introduced names the transitive packages rolled up onto this line, as
	// "name@version".
	Introduced []string

	// ExploitsGated records that the server withheld exploit intelligence rather
	// than reporting none. The two are the same empty section and opposite
	// claims.
	ExploitsGated bool

	Fix     Fix
	Insight *Insight
}

// Card renders the full dependency card as Markdown.
//
// A clean package still earns a card: the reassurance is the point of having
// checked.
func Card(s Subject) string {
	var b strings.Builder

	fmt.Fprintf(&b, "**%s**", s.Pkg.Label())
	if s.Pkg.Ecosystem != "" {
		fmt.Fprintf(&b, " · %s", s.Pkg.Ecosystem)
	}
	b.WriteString("\n")

	if len(s.Vulns) == 0 {
		// The reassurance is only honest when nothing is wrong. A package a
		// malware feed has named has no CVEs precisely because nobody files an
		// advisory against a package that should not exist, and printing "no
		// known vulnerabilities" above "malicious package" reads as a
		// contradiction that undermines both lines.
		if s.Insight == nil || !s.Insight.Malicious {
			b.WriteString("\nNo known vulnerabilities.\n")
		}
		writeInsightNotes(&b, s.Insight)
		return b.String()
	}

	b.WriteString("\n")
	counts := CountBySeverity(s.Vulns)
	b.WriteString(PluralVulns(len(s.Vulns)))
	if split := SeveritySplit(counts); split != "" {
		fmt.Fprintf(&b, " · %s", split)
	}
	b.WriteString("\n\n")

	writeVulnList(&b, s.Vulns)
	writeExploitSection(&b, s.Vulns, s.ExploitsGated)
	writeFixSection(&b, s.Fix)
	writeInsightNotes(&b, s.Insight)

	if len(s.Introduced) > 0 {
		b.WriteString("\n**Introduced transitively:** ")
		b.WriteString(strings.Join(s.Introduced, ", "))
		b.WriteString("\n")
	}

	return b.String()
}

// Headline renders the one-line message: what a reader scans for first, then
// how bad, then something to search.
//
// When the vulnerability is transitive the message says so rather than implying
// the named package is itself vulnerable.
func Headline(s Subject) string {
	var b strings.Builder

	fmt.Fprintf(&b, "%s: %s", s.Pkg.Label(), PluralVulns(len(s.Vulns)))

	if split := SeveritySplit(CountBySeverity(s.Vulns)); split != "" {
		fmt.Fprintf(&b, " (%s)", split)
	}

	if s.OwnVulns == 0 && len(s.Introduced) > 0 {
		fmt.Fprintf(&b, " introduced via %s", strings.Join(s.Introduced, ", "))
	} else if len(s.Introduced) > 0 {
		fmt.Fprintf(&b, ", including %s pulled in transitively", strings.Join(s.Introduced, ", "))
	}

	if top := TopVuln(s.Vulns); top.CveID != "" {
		fmt.Fprintf(&b, " — %s", top.CveID)
		if top.InCisaKev {
			b.WriteString(" (CISA KEV)")
		}
	}
	return b.String()
}

// writeVulnList renders the most severe advisories, worst first, so the head of
// this list is the advisory Headline names.
func writeVulnList(b *strings.Builder, vulns []scan.EnrichedVuln) {
	ordered := make([]scan.EnrichedVuln, len(vulns))
	copy(ordered, vulns)

	for i := 0; i < len(ordered); i++ {
		best := i
		for j := i + 1; j < len(ordered); j++ {
			if LessSevere(ordered[best], ordered[j]) {
				best = j
			}
		}
		ordered[i], ordered[best] = ordered[best], ordered[i]
	}

	shown := ordered
	if len(shown) > maxCardVulns {
		shown = shown[:maxCardVulns]
	}

	for _, v := range shown {
		fmt.Fprintf(b, "- `%s`", v.CveID)
		if sev := NormaliseSeverity(v.MaxSeverity); sev != "" {
			fmt.Fprintf(b, " **%s**", sev)
		}
		if v.CVSSScore > 0 {
			fmt.Fprintf(b, " · CVSS %.1f", v.CVSSScore)
		}
		if v.EPSSScore > 0 {
			fmt.Fprintf(b, " · EPSS %.1f%%", v.EPSSScore*100)
		}
		if v.InCisaKev {
			b.WriteString(" · **CISA KEV**")
		}
		b.WriteString("\n")
	}

	if len(ordered) > len(shown) {
		fmt.Fprintf(b, "- …and %d more\n", len(ordered)-len(shown))
	}
}

// writeExploitSection reports exploit intelligence, or says what would provide
// it.
//
// The distinction this preserves: "no exploits are known" and "exploit data was
// not part of this answer" look identical as an empty section, and the first is
// a far more reassuring claim than the second.
func writeExploitSection(b *strings.Builder, vulns []scan.EnrichedVuln, gated bool) {
	total := 0
	kev := false
	for _, v := range vulns {
		total += v.ExploitCount
		if v.InCisaKev || v.InVulnCheckKev || v.InEuKev {
			kev = true
		}
	}

	switch {
	case total > 0:
		fmt.Fprintf(b, "\n**Exploits:** %d known", total)
		if kev {
			b.WriteString(", listed as actively exploited")
		}
		b.WriteString("\n")
	case kev:
		b.WriteString("\n**Exploits:** listed as actively exploited\n")
	case gated:
		b.WriteString("\n*Pro unlocks exploit intel.*\n")
	default:
		b.WriteString("\n**Exploits:** none known\n")
	}
}

// writeFixSection renders the recommended bump, or the reason there is not one.
func writeFixSection(b *strings.Builder, f Fix) {
	switch f.State {
	case FixNotApplicable:
		return
	case FixGated:
		b.WriteString("\n*Pro unlocks Safe-Harbour version recommendations.*\n")
	case FixPending:
		b.WriteString("\n*Resolving safe versions…*\n")
	case FixNone:
		reason := f.Reason
		if reason == "" {
			reason = "no safe version available"
		}
		fmt.Fprintf(b, "\n**Fix:** none available — %s\n", reason)
	case FixAvailable:
		fmt.Fprintf(b, "\n**Quick fix:** bump to %s", f.Target)
		if reason := strings.TrimSpace(f.Reason); reason != "" {
			fmt.Fprintf(b, " — %s", reason)
		}
		b.WriteString("\n")
	}
}

func writeInsightNotes(b *strings.Builder, in *Insight) {
	if in == nil {
		return
	}
	if in.Malicious {
		b.WriteString("\n**Malicious package.** Remove it; a version bump is not a fix.\n")
	}
	if in.EOL {
		b.WriteString("\n**End of life")
		if from := strings.TrimSpace(in.EOLFrom); from != "" {
			fmt.Fprintf(b, " since %s", from)
		}
		b.WriteString(".** No further security updates are expected.\n")
	}
}

// PluralVulns renders a count with the right noun.
func PluralVulns(n int) string {
	if n == 1 {
		return "1 vulnerability"
	}
	return fmt.Sprintf("%d vulnerabilities", n)
}

// severityOrder is worst-first, which is both the sort order and the render
// order for the count split.
var severityOrder = []string{"critical", "high", "medium", "low", "info"}

// CountBySeverity tallies advisories by normalised severity label.
func CountBySeverity(vulns []scan.EnrichedVuln) map[string]int {
	counts := map[string]int{}
	for _, v := range vulns {
		counts[NormaliseSeverity(v.MaxSeverity)]++
	}
	return counts
}

// SeveritySplit renders "2 critical, 3 high", omitting the tail that carries no
// information: a reader deciding whether to act does not need the low count.
func SeveritySplit(counts map[string]int) string {
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

// WorstSeverity returns the most severe normalised label across the set.
func WorstSeverity(vulns []scan.EnrichedVuln) string {
	best := "info"
	bestRank := SeverityRank(best)
	for _, v := range vulns {
		if r := SeverityRank(v.MaxSeverity); r < bestRank {
			bestRank = r
			best = NormaliseSeverity(v.MaxSeverity)
		}
	}
	return best
}

// SeverityRank orders severities worst-first, so a lower rank is more severe.
func SeverityRank(severity string) int {
	target := NormaliseSeverity(severity)
	for i, label := range severityOrder {
		if label == target {
			return i
		}
	}
	return len(severityOrder)
}

// NormaliseSeverity folds vendor spellings onto the five labels used here.
func NormaliseSeverity(severity string) string {
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

// LessSevere reports whether a ranks below b, using the same ordering as
// TopVuln so a card's list and its headline agree.
func LessSevere(a, b scan.EnrichedVuln) bool {
	ra, rb := SeverityRank(a.MaxSeverity), SeverityRank(b.MaxSeverity)
	if ra != rb {
		return ra > rb
	}
	if a.InCisaKev != b.InCisaKev {
		return !a.InCisaKev
	}
	if ca, cb := IsCVE(a.CveID), IsCVE(b.CveID); ca != cb {
		return !ca
	}
	if a.ExploitCount != b.ExploitCount {
		return a.ExploitCount < b.ExploitCount
	}
	return a.CveID < b.CveID
}

// TopVuln picks the one vulnerability to name in a one-line message: most
// severe, then known-exploited, then a CVE over a database-specific identifier,
// then highest exploit count, then newest identifier.
//
// The CVE preference sits ahead of the exploit count rather than after it. The
// same advisory routinely arrives under both a CVE and a GHSA with different
// per-source exploit tallies, so ranking on the tally first picks a name by an
// accident of which database recorded more. The CVE is the name that appears in
// advisories, tickets and news, so it is the one worth showing.
//
// The last tiebreak is not arbitrary either. Among equally severe advisories the
// more recent one is the more useful thing to name, and ordering by identifier
// keeps the choice stable across scans.
func TopVuln(vulns []scan.EnrichedVuln) scan.EnrichedVuln {
	if len(vulns) == 0 {
		return scan.EnrichedVuln{}
	}
	sorted := make([]scan.EnrichedVuln, len(vulns))
	copy(sorted, vulns)

	sort.SliceStable(sorted, func(i, j int) bool {
		ri, rj := SeverityRank(sorted[i].MaxSeverity), SeverityRank(sorted[j].MaxSeverity)
		if ri != rj {
			return ri < rj
		}
		ki, kj := sorted[i].InCisaKev, sorted[j].InCisaKev
		if ki != kj {
			return ki
		}
		ci, cj := IsCVE(sorted[i].CveID), IsCVE(sorted[j].CveID)
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

// CVEIDs lists the distinct identifiers attributed to a line, sorted so the
// order is stable across scans.
func CVEIDs(vulns []scan.EnrichedVuln) []string {
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

// IsCVE reports whether an identifier is a CVE rather than a database-specific
// name.
func IsCVE(id string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(id)), "CVE-")
}

// SeverityKnown reports whether a label is one of the five this package ranks.
// An unrecognised severity floor is not a reason to hide anything, so callers
// filtering by severity check this before applying a rank comparison.
func SeverityKnown(severity string) bool {
	return SeverityRank(severity) < len(severityOrder)
}
