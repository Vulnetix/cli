package lsp

import (
	"strings"

	"github.com/vulnetix/cli/v3/internal/lsp/protocol"
	"github.com/vulnetix/cli/v3/internal/scaview"
)

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
				Value: scaview.Card(e.subject(a)),
			},
			Range: &rng,
		}
	}
	return nil
}

// subject projects an annotation onto the shared render input.
//
// This is the only place the engine's internal state is translated for display.
// The editor, the terminal and the agent hook all render from a scaview.Subject,
// so a wording change lands in every surface at once and a difference between
// them is not expressible.
func (e *scaEngine) subject(a *scaAnnotation) scaview.Subject {
	s := scaview.Subject{
		Pkg: scaview.Pkg{
			Name:      a.Pkg.Name,
			Version:   a.Pkg.Version,
			Ecosystem: a.Pkg.Ecosystem,
		},
		Vulns:         a.AllVulns(),
		Introduced:    introducedNames(a.Introduced),
		ExploitsGated: e.Gated(featureExploits),
		Fix:           e.fixFor(a),
	}

	if a.Verdict != nil {
		s.OwnVulns = len(a.Verdict.Vulns)
		if in := a.Verdict.Insight; in != nil && (in.IsMalicious || in.IsEOL) {
			s.Insight = &scaview.Insight{
				Malicious: in.IsMalicious,
				EOL:       in.IsEOL,
				EOLFrom:   strings.TrimSpace(in.EOLFrom),
			}
		}
	}

	return s
}

// fixFor resolves the upgrade recommendation, keeping the three ways it can be
// absent distinct: the lookup has not finished, the server does not provide
// ranked versions on this plan, or it does and there genuinely is none.
// Reporting the second as the third tells someone no fix exists when one may
// well.
func (e *scaEngine) fixFor(a *scaAnnotation) scaview.Fix {
	v := a.Verdict
	if v == nil || !v.Vulnerable() {
		return scaview.Fix{State: scaview.FixNotApplicable}
	}

	if e.Gated(featureSafeVersions) {
		return scaview.Fix{State: scaview.FixGated}
	}

	switch v.SafeState {
	case safeUnrequested, safePending:
		return scaview.Fix{State: scaview.FixPending}
	}

	target, decision := resolveFixTarget(v, e.settings())
	if decision.Skipped || target == "" {
		return scaview.Fix{State: scaview.FixNone, Reason: decision.Reason}
	}

	f := scaview.Fix{State: scaview.FixAvailable, Target: target}
	if v.Insight != nil && v.Insight.SafeHarbour != nil && v.Insight.SafeHarbour.Recommendation != nil {
		f.Reason = strings.TrimSpace(v.Insight.SafeHarbour.Recommendation.Reason)
	}
	return f
}
