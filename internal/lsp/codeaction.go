package lsp

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vulnetix/cli/v3/internal/fix"
	"github.com/vulnetix/cli/v3/internal/lsp/protocol"
	"github.com/vulnetix/cli/v3/internal/lsp/rangefix"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// maxFixAlternatives caps how many versions are offered beyond the recommended
// one. Safe-Harbour can return a long ranked list; a lightbulb menu with twenty
// entries is not a choice, it is a wall.
const maxFixAlternatives = 3

// resolveFixTarget picks the version a fix should move a package to.
//
// Delegates to internal/fix so the editor's answer is the same one `vulnetix
// fix` would give for the same strategy, rather than a second implementation
// that drifts.
func resolveFixTarget(v *scaVerdict, cfg scaSettings) (string, fix.TargetDecision) {
	if v == nil || v.Insight == nil {
		return "", fix.TargetDecision{Skipped: true, Reason: "safe versions not resolved yet"}
	}
	return fix.ResolveTarget(
		v.Version,
		cfg.Strategy,
		v.Insight.LatestVersions,
		v.Insight.SafeVersions,
		v.Insight.SafeHarbour,
		cfg.MaxMajorBump,
	)
}

// CodeActions offers version bumps for the dependencies overlapping a range.
//
// The actions edit the manifest and nothing else. Running a package manager is
// deliberately not offered: it mutates a lockfile and the install tree, which
// is not something an editor should do from a lightbulb.
func (e *scaEngine) CodeActions(relPath, text, uri string, requested protocol.Range) []protocol.CodeAction {
	cfg := e.settings()
	if !cfg.Enabled {
		return nil
	}

	lines := rangefix.SplitLines(text)
	annotations := e.Annotations(relPath, text)

	var out []protocol.CodeAction
	for i := range annotations {
		a := &annotations[i]
		if !overlaps(a.Range, requested) {
			continue
		}
		// A transitive-only finding has no version on this line to change. The
		// fix is to bump the parent, which is the annotation that carries it.
		if a.Verdict == nil || !a.Verdict.Vulnerable() {
			continue
		}
		out = append(out, e.actionsForPackage(a, lines, uri, cfg)...)
	}
	return out
}

// actionsForPackage builds the ranked list of version bumps for one dependency.
func (e *scaEngine) actionsForPackage(a *scaAnnotation, lines []string, uri string, cfg scaSettings) []protocol.CodeAction {
	v := a.Verdict
	if v.Insight == nil {
		return nil
	}

	target, decision := resolveFixTarget(v, cfg)
	if decision.Skipped && target == "" {
		return nil
	}

	candidates := rankedCandidates(v, target, cfg)
	out := make([]protocol.CodeAction, 0, len(candidates))

	for idx, c := range candidates {
		edit, ok := e.manifestEdit(a, lines, uri, c.Version)
		if !ok {
			continue
		}
		out = append(out, protocol.CodeAction{
			Title:       fixTitle(a.Pkg.Name, a.Pkg.Version, c),
			Kind:        protocol.CodeActionQuickFix,
			IsPreferred: idx == 0,
			Edit:        edit,
		})
	}
	return out
}

// fixCandidate is one offered version plus the evidence for offering it.
type fixCandidate struct {
	Version string
	// Remaining is how many known vulnerabilities survive the bump. Zero is the
	// point of the exercise; non-zero is still worth offering when nothing
	// cleaner exists, but the user should be told.
	Remaining int
	Score     float64
	HasScore  bool
	Malware   bool
}

// rankedCandidates puts the resolved target first, then the next best
// Safe-Harbour versions.
//
// The target leads regardless of score because it is the one that honours the
// configured strategy and the major-bump cap; the alternatives exist for the
// case where the user knows something the policy does not.
func rankedCandidates(v *scaVerdict, target string, cfg scaSettings) []fixCandidate {
	safe := v.Insight.SafeVersions

	byVersion := make(map[string]vdb.CliSafeHarbourVersion, len(safe))
	for _, s := range safe {
		byVersion[s.Version] = s
	}

	out := make([]fixCandidate, 0, maxFixAlternatives+1)
	seen := map[string]bool{}

	add := func(version string) {
		if version == "" || version == v.Version || seen[version] {
			return
		}
		s, known := byVersion[version]
		// A version the server flagged as malware is never offered, whatever
		// its rank. Recommending a malicious package to fix a vulnerable one is
		// the worst outcome this feature has available.
		if known && s.IsMalware {
			return
		}
		seen[version] = true
		out = append(out, fixCandidate{
			Version:   version,
			Remaining: s.VulnerabilityCount,
			Score:     s.SafeHarbourScore,
			HasScore:  known && s.SafeHarbourScore > 0,
			Malware:   known && s.IsMalware,
		})
	}

	add(target)

	ranked := make([]vdb.CliSafeHarbourVersion, len(safe))
	copy(ranked, safe)
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].VulnerabilityCount != ranked[j].VulnerabilityCount {
			return ranked[i].VulnerabilityCount < ranked[j].VulnerabilityCount
		}
		return ranked[i].SafeHarbourScore > ranked[j].SafeHarbourScore
	})
	for _, s := range ranked {
		if len(out) > maxFixAlternatives {
			break
		}
		add(s.Version)
	}

	return out
}

// fixTitle names the action in the lightbulb menu.
func fixTitle(name, current string, c fixCandidate) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Bump %s %s → %s", name, current, c.Version)

	switch {
	case c.Remaining == 0 && c.HasScore:
		fmt.Fprintf(&b, " (no known vulnerabilities, Safe-Harbour %.0f)", c.Score)
	case c.Remaining == 0:
		b.WriteString(" (no known vulnerabilities)")
	case c.Remaining == 1:
		b.WriteString(" (1 known vulnerability remains)")
	default:
		fmt.Fprintf(&b, " (%d known vulnerabilities remain)", c.Remaining)
	}
	return b.String()
}

// manifestEdit computes the text edit that performs the bump.
//
// The rewrite itself is internal/fix's, which is what `vulnetix fix` applies —
// including preserving a declared range operator, so `^4.17.20` becomes
// `^4.17.21` rather than a hard pin the user did not ask for. Only the changed
// lines are sent: replacing the whole document would collapse the user's undo
// history into one step and fight any concurrent edit.
func (e *scaEngine) manifestEdit(a *scaAnnotation, lines []string, uri, target string) (*protocol.WorkspaceEdit, bool) {
	original := strings.Join(lines, "\n")

	candidate := fix.FixCandidate{
		PackageName: a.Pkg.Name,
		Ecosystem:   a.Pkg.Ecosystem,
		CurrentVer:  a.Pkg.Version,
		SourceFile:  a.Pkg.SourceFile,
		IsDirect:    a.Pkg.IsDirect,
		TargetVer:   target,
	}

	updated, changed := fix.EditManifestText(original, candidate)
	if !changed || updated == original {
		return nil, false
	}

	edits := diffLineEdits(lines, rangefix.SplitLines(updated))
	if len(edits) == 0 {
		return nil, false
	}

	return &protocol.WorkspaceEdit{
		Changes: map[string][]protocol.TextEdit{uri: edits},
	}, true
}

// diffLineEdits reduces a whole-file rewrite to the smallest span that changed.
//
// A line-level diff rather than a character one: the rewriters work on whole
// lines, and a single replaced span is both correct and what the editor's undo
// stack wants.
func diffLineEdits(before, after []string) []protocol.TextEdit {
	start := 0
	for start < len(before) && start < len(after) && before[start] == after[start] {
		start++
	}
	if start == len(before) && start == len(after) {
		return nil
	}

	endBefore := len(before)
	endAfter := len(after)
	for endBefore > start && endAfter > start && before[endBefore-1] == after[endAfter-1] {
		endBefore--
		endAfter--
	}

	replacement := strings.Join(after[start:endAfter], "\n")

	// The replaced span ends at the start of the first unchanged line, so the
	// trailing newline is preserved rather than eaten.
	rng := protocol.Range{
		Start: protocol.Position{Line: start, Character: 0},
		End:   protocol.Position{Line: endBefore, Character: 0},
	}
	if endBefore < len(before) || endAfter < len(after) {
		replacement += "\n"
	} else {
		rng.End = protocol.Position{
			Line:      endBefore - 1,
			Character: utf16Width(before[endBefore-1]),
		}
	}

	return []protocol.TextEdit{{Range: rng, NewText: replacement}}
}

// utf16Width measures a line in UTF-16 code units, the unit LSP positions use.
func utf16Width(s string) int {
	n := 0
	for _, r := range s {
		if r > 0xFFFF {
			n += 2
			continue
		}
		n++
	}
	return n
}

// overlaps reports whether two ranges intersect, treating a zero-width request
// (a cursor) as touching the line it sits on.
func overlaps(a, b protocol.Range) bool {
	if a.End.Line < b.Start.Line || b.End.Line < a.Start.Line {
		return false
	}
	return true
}
