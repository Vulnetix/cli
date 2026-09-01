package lsp

import (
	"fmt"

	"github.com/vulnetix/cli/v3/internal/lsp/protocol"
	"github.com/vulnetix/cli/v3/internal/lsp/rangefix"
)

// Inline markers. Text rather than icons: an inlay hint is a string, and these
// have to stay legible in a terminal-rendered editor and at any font.
const (
	// hintChecked is the quiet confirmation on a dependency the bulk check
	// cleared. It exists so a clean manifest looks checked rather than looking
	// unscanned — the two are indistinguishable without it, and the difference
	// matters.
	hintChecked = "✓"
	// hintPending marks a vulnerable package whose replacement versions are
	// still being resolved, so the absence of a fix reads as "not yet" rather
	// than "none exists".
	hintPending = "⋯ safe versions"
)

// InlayHints renders the per-dependency status markers for a document.
//
// Vulnerabilities are not reported here: they are diagnostics, and duplicating
// them as hints would double every finding on screen. The hints carry what a
// diagnostic cannot, because none of it is a problem — that a package was
// checked and is clean, that a lookup is still running, and what version a fix
// would move to.
func (e *scaEngine) InlayHints(relPath, text string, requested protocol.Range) []protocol.InlayHint {
	cfg := e.settings()
	if !cfg.Enabled || !e.Ready() {
		// Before the first bulk pass nothing is known, and a checkmark on an
		// unchecked dependency is a false statement.
		return nil
	}

	lines := rangefix.SplitLines(text)
	annotations := e.Annotations(relPath, text)

	out := make([]protocol.InlayHint, 0, len(annotations))
	for i := range annotations {
		a := &annotations[i]
		if a.Range.End.Line < requested.Start.Line || a.Range.Start.Line > requested.End.Line {
			continue
		}
		hint, ok := e.hintFor(a, lines)
		if !ok {
			continue
		}
		out = append(out, hint)
	}
	return out
}

func (e *scaEngine) hintFor(a *scaAnnotation, lines []string) (protocol.InlayHint, bool) {
	label, tooltip, ok := e.hintLabel(a)
	if !ok {
		return protocol.InlayHint{}, false
	}

	line := a.Range.End.Line
	if line < 0 || line >= len(lines) {
		return protocol.InlayHint{}, false
	}

	return protocol.InlayHint{
		// End of the declaration line, so the marker never displaces code.
		Position:    protocol.Position{Line: line, Character: utf16Width(lines[line])},
		Label:       label,
		Kind:        protocol.InlayHintType,
		Tooltip:     tooltip,
		PaddingLeft: true,
	}, true
}

// hintLabel decides which of the three states a dependency is in.
func (e *scaEngine) hintLabel(a *scaAnnotation) (label, tooltip string, ok bool) {
	if a.Verdict == nil {
		// Declared but absent from the bulk result: the lookup could not
		// resolve it. Silence is right — a marker either way would be a claim
		// the engine cannot support.
		return "", "", false
	}

	if !a.Vulnerable() {
		return hintChecked, fmt.Sprintf("%s@%s: no known vulnerabilities",
			a.Pkg.Name, a.Pkg.Version), true
	}

	if e.Gated(featureSafeVersions) {
		// No replacement version is coming on this plan, so a pending marker
		// would spin forever and a target marker would be a fabrication. The
		// diagnostic already reports the vulnerability; the hover explains what
		// would provide the fix.
		return "", "", false
	}

	if a.Pending() {
		return hintPending, fmt.Sprintf("%s@%s: resolving safe versions",
			a.Pkg.Name, a.Pkg.Version), true
	}

	target := e.targetVersionFor(a.Verdict)
	if target == "" {
		return "", "", false
	}
	return "→ " + target, fmt.Sprintf("Safe-Harbour target for %s@%s",
		a.Pkg.Name, a.Pkg.Version), true
}
