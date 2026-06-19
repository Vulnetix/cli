package fix

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/vulnetix/cli/v3/internal/scan"
)

func resolveTransitive(fc *FixCandidate, groups []scan.ManifestGroup) {
	if fc.TargetVer == "" {
		fc.Skipped = true
		if fc.SkipReason == "" {
			fc.SkipReason = "no target version for transitive dependency"
		}
		return
	}
	for _, g := range groups {
		if g.Graph == nil || !groupContainsFile(g, fc.SourceFile) {
			continue
		}
		for _, parent := range immediateParents(g.Graph, fc.PackageName) {
			rng := ""
			if g.Graph.EdgeRanges != nil && g.Graph.EdgeRanges[parent] != nil {
				rng = g.Graph.EdgeRanges[parent][fc.PackageName]
			}
			fc.ParentName = parent
			fc.ParentRange = rng
			// (a) parent-update — a Safe-Harbour child already satisfies the
			// parent's declared range, so re-resolving the lockfile is enough.
			if rng != "" && Satisfies(fc.TargetVer, rng) {
				fc.Method = MethodParentUpdate
				fc.Command = npmTransitiveCommand(MethodParentUpdate, parent, "")
				fc.Reason = fmt.Sprintf("%s@%s satisfies %s's declared range %q", fc.PackageName, fc.TargetVer, parent, rng)
				return
			}
			// (b) parent-upgrade — finding a parent version whose declared range
			// admits the safe child requires per-version registry metadata. That
			// resolution is now performed server-side (cross-ecosystem) and arrives
			// as a TransitiveFixRecommendation; the CLI no longer queries a registry
			// directly. Without a recommendation we fall through to the deterministic
			// override below.
		}
	}
	// (c) deterministic override/pin — force the resolver to select the safe child
	// version via the ecosystem's override / pin / update mechanism. This is the
	// reliable, cross-ecosystem fix for deep transitive chains with no editable
	// parent path. Every supported ecosystem resolves here rather than skipping;
	// the per-ecosystem manifest edit (or, for go/cargo, the install command
	// itself) is applied during Apply/RunInstall.
	fc.Method = MethodOverride
	fc.Skipped = false
	fc.Reason = fmt.Sprintf("pin %s to %s via %s (no editable parent path resolved the chain)", fc.PackageName, fc.TargetVer, overrideMechanism(fc.Ecosystem))
	if strings.EqualFold(fc.Ecosystem, "npm") {
		// Placeholder; cmd rewrites this to the concrete `<pm> install` after the
		// package.json override is written.
		fc.Command = overrideInstallNote
		return
	}
	fc.Command = commandFor(*fc, fc.TargetVer)
}

// overrideMechanism returns a human-readable label for how the override pin is
// realised for the ecosystem, used in the proof-of-work reason text.
func overrideMechanism(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return "a package-manager override"
	case "pypi":
		return "a pinned requirement"
	case "golang":
		return "go get + go mod tidy"
	case "cargo":
		return "cargo update --precise"
	case "maven":
		return "a <dependencyManagement> pin"
	case "composer":
		return "a composer require constraint"
	case "rubygems":
		return "a pinned Gemfile entry"
	default:
		return "a package-manager pin"
	}
}

// overrideInstallNote is a placeholder command for override plans; the real
// install command is set per package-manager during command rewriting.
const overrideInstallNote = "# pin via package-manager override, then install"

func groupContainsFile(g scan.ManifestGroup, file string) bool {
	return slices.Contains(g.Files, file)
}

// immediateParents returns the distinct immediate parents of target that are
// reachable from a direct dependency: every node that declares an edge to target
// and is itself reachable from the manifest's direct deps.
//
// This replaces an earlier routine (allPathsTo/walkGraph) that enumerated *every*
// simple path from each direct dep to the target — exponential on real dependency
// graphs, and the cause of a multi-hour autofix hang. Only the immediate parent
// (path[len-2]) of each path was ever consumed, so the full set of those parents
// is all that is needed. A single O(V+E) BFS from the direct deps yields it.
//
// Matching is case-insensitive to mirror the previous behaviour (edge keys from
// "go mod graph" etc. may differ in case from the package name). The order is
// sorted for determinism; the old path order was already non-deterministic (it
// ranged over the DirectDeps map), so callers must not rely on a specific order.
func immediateParents(g *scan.DepGraph, target string) []string {
	if g == nil || len(g.Edges) == 0 {
		return nil
	}
	visited := make(map[string]bool, len(g.DirectDeps))
	queue := make([]string, 0, len(g.DirectDeps))
	for name := range g.DirectDeps {
		if !visited[name] {
			visited[name] = true
			queue = append(queue, name)
		}
	}
	parents := map[string]bool{}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, child := range g.Edges[cur] {
			if strings.EqualFold(child, target) {
				parents[cur] = true
			}
			if !visited[child] {
				visited[child] = true
				queue = append(queue, child)
			}
		}
	}
	out := make([]string, 0, len(parents))
	for p := range parents {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
