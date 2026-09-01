package lsp

import (
	"fmt"
	"strings"

	"github.com/vulnetix/cli/v3/internal/lsp/protocol"
	"github.com/vulnetix/cli/v3/internal/scan"
)

// maxHoverVulns caps the vulnerability list in a hover card. A dependency with
// forty advisories produces a card taller than the editor window, and the ones
// past the top few are not what decides whether to act.
const maxHoverVulns = 5

// Feature names the server uses in its tier-gating map.
//
// A feature listed there was asked for and deliberately not answered, which is
// a different thing from being asked for and found empty. Everything that
// renders an absence has to tell the two apart.
const (
	featureSafeVersions = "safeVersions"
	featureExploits     = "exploits"
)

// Hover renders the dependency card for a position in a manifest.
//
// Returns nil when the position is not on a dependency the engine knows about,
// which the caller sends as a null result rather than an empty card.
func (e *scaEngine) Hover(relPath, text string, pos protocol.Position) *protocol.Hover {
	if !e.settings().Enabled {
		return nil
	}

	annotations := e.Annotations(relPath, text)
	for i := range annotations {
		a := &annotations[i]
		if pos.Line < a.Range.Start.Line || pos.Line > a.Range.End.Line {
			continue
		}
		rng := a.Range
		return &protocol.Hover{
			Contents: protocol.MarkupContent{
				Kind:  protocol.MarkupMarkdown,
				Value: e.hoverMarkdown(a),
			},
			Range: &rng,
		}
	}
	return nil
}

func (e *scaEngine) hoverMarkdown(a *scaAnnotation) string {
	var b strings.Builder

	fmt.Fprintf(&b, "**%s@%s**", a.Pkg.Name, a.Pkg.Version)
	if a.Pkg.Ecosystem != "" {
		fmt.Fprintf(&b, " · %s", a.Pkg.Ecosystem)
	}
	b.WriteString("\n\n")

	vulns := a.AllVulns()
	if len(vulns) == 0 {
		// A clean package still earns a card: the reassurance is the point of
		// having checked.
		b.WriteString("No known vulnerabilities.\n")
		e.writeInsightNotes(&b, a)
		return b.String()
	}

	counts := countBySeverityLabel(vulns)
	fmt.Fprintf(&b, "%s", pluralVulns(len(vulns)))
	if split := severitySplit(counts); split != "" {
		fmt.Fprintf(&b, " · %s", split)
	}
	b.WriteString("\n\n")

	writeVulnList(&b, vulns)
	e.writeExploitSection(&b, vulns)
	e.writeFixSection(&b, a)
	e.writeInsightNotes(&b, a)

	if len(a.Introduced) > 0 {
		b.WriteString("\n**Introduced transitively:** ")
		b.WriteString(strings.Join(introducedNames(a.Introduced), ", "))
		b.WriteString("\n")
	}

	return b.String()
}

// writeVulnList renders the most severe advisories, worst first.
func writeVulnList(b *strings.Builder, vulns []scan.EnrichedVuln) {
	ordered := make([]scan.EnrichedVuln, len(vulns))
	copy(ordered, vulns)

	// Selection sort against the same comparison topVuln uses, so the head of
	// this list is the advisory the diagnostic headline names.
	for i := 0; i < len(ordered); i++ {
		best := i
		for j := i + 1; j < len(ordered); j++ {
			if lessSevere(ordered[best], ordered[j]) {
				best = j
			}
		}
		ordered[i], ordered[best] = ordered[best], ordered[i]
	}

	shown := ordered
	if len(shown) > maxHoverVulns {
		shown = shown[:maxHoverVulns]
	}

	for _, v := range shown {
		fmt.Fprintf(b, "- `%s`", v.CveID)
		if sev := normaliseSeverity(v.MaxSeverity); sev != "" {
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

// lessSevere reports whether a ranks below b, using the same ordering as
// topVuln so the hover list and the diagnostic headline agree.
func lessSevere(a, b scan.EnrichedVuln) bool {
	ra, rb := severityRank(a.MaxSeverity), severityRank(b.MaxSeverity)
	if ra != rb {
		return ra > rb
	}
	if a.InCisaKev != b.InCisaKev {
		return !a.InCisaKev
	}
	if ca, cb := isCVE(a.CveID), isCVE(b.CveID); ca != cb {
		return !ca
	}
	if a.ExploitCount != b.ExploitCount {
		return a.ExploitCount < b.ExploitCount
	}
	return a.CveID < b.CveID
}

// writeExploitSection reports exploit intelligence, or says what would provide
// it.
//
// The distinction this preserves: "no exploits are known" and "exploit data was
// not part of this answer" look identical as an empty section, and the first is
// a far more reassuring claim than the second. Which applies is read from what
// the server said it withheld rather than from the plan name — the tier is the
// server's to know, and it reports gating per feature rather than as one flag.
func (e *scaEngine) writeExploitSection(b *strings.Builder, vulns []scan.EnrichedVuln) {
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
	case e.Gated(featureExploits):
		b.WriteString("\n*Pro unlocks exploit intel.*\n")
	default:
		b.WriteString("\n**Exploits:** none known\n")
	}
}

// writeFixSection renders the recommended bump, or the reason there is not one.
//
// Three outcomes that must not be confused with each other: the lookup has not
// finished, the server does not provide ranked versions on this plan, or it
// does and there genuinely is none. Reporting the second as the third tells
// someone no fix exists when one may well.
func (e *scaEngine) writeFixSection(b *strings.Builder, a *scaAnnotation) {
	v := a.Verdict
	if v == nil || !v.Vulnerable() {
		return
	}

	if e.Gated(featureSafeVersions) {
		b.WriteString("\n*Pro unlocks Safe-Harbour version recommendations.*\n")
		return
	}

	switch v.SafeState {
	case safeUnrequested, safePending:
		b.WriteString("\n*Resolving safe versions…*\n")
		return
	}

	target, decision := resolveFixTarget(v, e.settings())
	if decision.Skipped || target == "" {
		reason := decision.Reason
		if reason == "" {
			reason = "no safe version available"
		}
		fmt.Fprintf(b, "\n**Fix:** none available — %s\n", reason)
		return
	}

	fmt.Fprintf(b, "\n**Quick fix:** bump to %s", target)
	if v.Insight != nil && v.Insight.SafeHarbour != nil && v.Insight.SafeHarbour.Recommendation != nil {
		if reason := strings.TrimSpace(v.Insight.SafeHarbour.Recommendation.Reason); reason != "" {
			fmt.Fprintf(b, " — %s", reason)
		}
	}
	b.WriteString("\n")
}

// writeInsightNotes adds the flags that are not vulnerabilities but change what
// the right action is.
func (e *scaEngine) writeInsightNotes(b *strings.Builder, a *scaAnnotation) {
	v := a.Verdict
	if v == nil || v.Insight == nil {
		return
	}
	if v.Insight.IsMalicious {
		b.WriteString("\n**Malicious package.** Remove it; a version bump is not a fix.\n")
	}
	if v.Insight.IsEOL {
		b.WriteString("\n**End of life")
		if from := strings.TrimSpace(v.Insight.EOLFrom); from != "" {
			fmt.Fprintf(b, " since %s", from)
		}
		b.WriteString(".** No further security updates are expected.\n")
	}
}
