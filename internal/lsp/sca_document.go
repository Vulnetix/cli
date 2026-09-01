package lsp

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/vulnetix/cli/v3/internal/lsp/anchor"
	"github.com/vulnetix/cli/v3/internal/lsp/protocol"
	"github.com/vulnetix/cli/v3/internal/lsp/rangefix"
	"github.com/vulnetix/cli/v3/internal/scan"
)

// maxRollupDepth bounds how far a transitive chain is followed when attributing
// a lockfile finding to the manifest line that pulled it in.
//
// Bounded rather than exhaustive because the value of the attribution falls off
// sharply with distance: "express pulls in a vulnerable qs" is actionable, and
// "express pulls in something that pulls in something that pulls in a
// vulnerable qs" is a research task the editor cannot help with.
const maxRollupDepth = 6

// scaAnnotation is one declared package resolved against the current buffer.
//
// Every dependency feature is built from this one type, so the squiggle, the
// hover card, the quick fix and the inline marker cannot disagree about which
// line a package is on or what is wrong with it.
type scaAnnotation struct {
	Pkg     scan.ScopedPackage
	Verdict *scaVerdict

	Anchor anchor.Result
	Range  protocol.Range
	// Confidence is the combined verdict of the anchor and the column
	// synthesis: exact only when both were exact.
	Confidence anchor.Confidence

	// Introduced holds vulnerable transitive packages this declaration pulls in,
	// populated only when a lockfile supplied a dependency graph. Surfacing them
	// here is what makes a lockfile-only finding actionable: the version the
	// user can change is the one in the manifest.
	Introduced []*scaVerdict
}

// Vulnerable reports whether this line has anything to say.
func (a *scaAnnotation) Vulnerable() bool {
	return (a.Verdict != nil && a.Verdict.Vulnerable()) || len(a.Introduced) > 0
}

// Pending reports whether a Safe-Harbour lookup is still in flight for anything
// on this line, which is what the editor renders as a loading marker.
func (a *scaAnnotation) Pending() bool {
	if a.Verdict != nil && a.Verdict.Vulnerable() && a.Verdict.SafeState == safePending {
		return true
	}
	for _, v := range a.Introduced {
		if v.SafeState == safePending {
			return true
		}
	}
	return false
}

// AllVulns returns this line's own findings followed by the rolled-up ones.
func (a *scaAnnotation) AllVulns() []scan.EnrichedVuln {
	var out []scan.EnrichedVuln
	if a.Verdict != nil {
		out = append(out, a.Verdict.Vulns...)
	}
	for _, v := range a.Introduced {
		out = append(out, v.Vulns...)
	}
	return out
}

// Annotations resolves every package declared by a manifest against the text
// the editor currently holds.
//
// text is the live buffer rather than the file on disk, so an annotation lands
// on the line the user is looking at even when the parse that produced the
// package list ran against an earlier version of the file. A package whose
// declaration cannot be located is dropped: a dependency finding rendered
// confidently on the wrong line is worse than a missing one.
func (e *scaEngine) Annotations(relPath, text string) []scaAnnotation {
	e.mu.Lock()
	packages := e.packagesByFile[relPath]
	manifestType := e.typeByFile[relPath]
	cfg := e.cfg
	e.mu.Unlock()

	if manifestType == "" || len(packages) == 0 || !cfg.Enabled {
		return nil
	}
	if isLockfileType(manifestType) && !cfg.AnnotateLockfiles {
		return nil
	}

	lines := rangefix.SplitLines(text)
	rollups := e.rollupIndex(relPath)

	seen := map[string]bool{}
	out := make([]scaAnnotation, 0, len(packages))

	for _, p := range packages {
		// One annotation per declaration site. A manifest that names the same
		// package twice still gets one squiggle.
		key := p.Name + "@" + p.Version
		if seen[key] {
			continue
		}

		found, ok := anchor.Find(text, manifestType, p.Name)
		if !ok {
			continue
		}
		seen[key] = true

		placed, ok := rangefix.Columns(lines, found.Line, found.Line, rangefix.Options{
			Snippet: found.Snippet,
		})
		if !ok {
			continue
		}

		verdict, _ := e.VerdictFor(p.Name, p.Version, p.Ecosystem)

		out = append(out, scaAnnotation{
			Pkg:        p,
			Verdict:    verdict,
			Anchor:     found,
			Range:      toProtocolRange(placed.Range),
			Confidence: combineConfidence(found.Confidence, placed.Confidence),
			Introduced: rollups[p.Name],
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Range.Start.Line != out[j].Range.Start.Line {
			return out[i].Range.Start.Line < out[j].Range.Start.Line
		}
		return out[i].Pkg.Name < out[j].Pkg.Name
	})
	return out
}

// rollupIndex maps each direct dependency of a manifest to the vulnerable
// transitive packages it introduces.
//
// Only produced when a lockfile supplied the graph. Without one there is no
// evidence for the claim, and guessing a parent would point the quick fix at
// the wrong package.
func (e *scaEngine) rollupIndex(relPath string) map[string][]*scaVerdict {
	e.mu.Lock()
	groups := e.groups
	verdicts := make(map[string]*scaVerdict, len(e.verdicts))
	for k, v := range e.verdicts {
		verdicts[k] = v
	}
	e.mu.Unlock()

	dir := filepath.ToSlash(filepath.Dir(relPath))
	out := map[string][]*scaVerdict{}

	// Vulnerable packages indexed by bare name, since a dependency graph names
	// modules rather than purls.
	vulnerableByName := map[string][]*scaVerdict{}
	for _, v := range verdicts {
		if v.Vulnerable() {
			vulnerableByName[v.Name] = append(vulnerableByName[v.Name], v)
		}
	}

	for _, g := range groups {
		if filepath.ToSlash(g.Dir) != dir || g.Graph == nil || len(g.Graph.Edges) == 0 {
			continue
		}
		for parent := range g.Graph.DirectDeps {
			found := collectVulnerableDescendants(g.Graph, parent, vulnerableByName)
			if len(found) > 0 {
				out[parent] = append(out[parent], found...)
			}
		}
	}
	return out
}

// collectVulnerableDescendants walks the dependency edges below a direct
// dependency, returning the vulnerable packages it reaches.
//
// Breadth-first with a visited set: dependency graphs contain cycles, and a
// naive walk over one does not terminate.
func collectVulnerableDescendants(graph *scan.DepGraph, root string, vulnerable map[string][]*scaVerdict) []*scaVerdict {
	visited := map[string]bool{root: true}
	frontier := []string{root}

	var out []*scaVerdict
	emitted := map[string]bool{}

	for depth := 0; depth < maxRollupDepth && len(frontier) > 0; depth++ {
		var next []string
		for _, node := range frontier {
			for _, child := range graph.Edges[node] {
				if visited[child] {
					continue
				}
				visited[child] = true
				next = append(next, child)

				for _, v := range vulnerable[child] {
					if emitted[v.Purl] {
						continue
					}
					emitted[v.Purl] = true
					out = append(out, v)
				}
			}
		}
		frontier = next
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Purl < out[j].Purl })
	return out
}

// isLockfileType reports whether a manifest type is a lockfile, which decides
// whether the annotateLockfiles setting applies.
func isLockfileType(manifestType string) bool {
	lower := strings.ToLower(manifestType)
	switch {
	case strings.Contains(lower, ".lock"), strings.HasSuffix(lower, "lock.json"),
		strings.HasSuffix(lower, "lock.yaml"), lower == "gemfile.lock",
		lower == "go.sum", lower == "package-lock.json", lower == "npm-shrinkwrap.json",
		lower == "packages.lock.json", lower == "package.resolved":
		return true
	}
	return false
}

// combineConfidence reports exact only when both the line and the column were
// derived exactly. Anything softer is token, so the client never renders an
// approximate anchor as a precise one.
func combineConfidence(line anchor.Confidence, columns rangefix.Confidence) anchor.Confidence {
	if line == anchor.ConfidenceExact && columns == rangefix.ConfidenceExact {
		return anchor.ConfidenceExact
	}
	return anchor.ConfidenceToken
}

func toProtocolRange(r rangefix.Range) protocol.Range {
	return protocol.Range{
		Start: protocol.Position{Line: r.Start.Line, Character: r.Start.Character},
		End:   protocol.Position{Line: r.End.Line, Character: r.End.Character},
	}
}
