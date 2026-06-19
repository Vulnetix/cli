package fix

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulnetix/cli/v3/internal/scan"
)

// TestImmediateParentsDedupesAndStaysReachable verifies the replacement for the
// old exponential allPathsTo/walkGraph: it returns the distinct immediate parents
// of the target that are reachable from a direct dependency, deduped and sorted.
func TestImmediateParentsDedupesAndStaysReachable(t *testing.T) {
	g := &scan.DepGraph{
		DirectDeps: map[string]scan.ScopedPackage{"a": {}, "b": {}},
		Edges: map[string][]string{
			"a":      {"c", "target"}, // a is itself an immediate parent
			"c":      {"target"},      // and reaches target via c too
			"b":      {"d"},
			"d":      {"target"},
			"target": {"a"}, // cycle back to a — must not loop forever
		},
	}
	got := immediateParents(g, "target")
	require.Equal(t, []string{"a", "c", "d"}, got)
}

// TestImmediateParentsMatchesCaseInsensitively mirrors the previous EqualFold
// behaviour (edge keys from "go mod graph" may differ in case).
func TestImmediateParentsMatchesCaseInsensitively(t *testing.T) {
	g := &scan.DepGraph{
		DirectDeps: map[string]scan.ScopedPackage{"a": {}},
		Edges:      map[string][]string{"a": {"Target"}},
	}
	require.Equal(t, []string{"a"}, immediateParents(g, "target"))
}

// TestImmediateParentsExcludesUnreachable: a node with an edge to target that is
// not reachable from any direct dep was never surfaced by the old path walk and
// must not be surfaced now.
func TestImmediateParentsExcludesUnreachable(t *testing.T) {
	g := &scan.DepGraph{
		DirectDeps: map[string]scan.ScopedPackage{"a": {}},
		Edges: map[string][]string{
			"a": {"c"},      // a -> c, neither reaches target
			"x": {"target"}, // x -> target, but x is unreachable from "a"
		},
	}
	require.Empty(t, immediateParents(g, "target"))
}

func TestImmediateParentsNilOrEmpty(t *testing.T) {
	require.Nil(t, immediateParents(nil, "target"))
	require.Nil(t, immediateParents(&scan.DepGraph{DirectDeps: map[string]scan.ScopedPackage{"a": {}}}, "target"))
}

// TestResolveTransitiveParentUpdateUsesImmediateParent confirms resolveTransitive
// still selects the parent-update method when an immediate parent's declared range
// already admits the safe child — now sourced via immediateParents.
func TestResolveTransitiveParentUpdateUsesImmediateParent(t *testing.T) {
	g := &scan.DepGraph{
		DirectDeps: map[string]scan.ScopedPackage{"parent": {Name: "parent"}},
		Edges:      map[string][]string{"parent": {"child"}},
		EdgeRanges: map[string]map[string]string{"parent": {"child": "^4.0.0"}},
	}
	group := scan.ManifestGroup{Files: []string{"package.json"}, Graph: g}
	fc := &FixCandidate{
		PackageName: "child",
		Ecosystem:   "npm",
		SourceFile:  "package.json",
		TargetVer:   "4.17.21",
	}
	resolveTransitive(fc, []scan.ManifestGroup{group})
	require.False(t, fc.Skipped)
	require.Equal(t, MethodParentUpdate, fc.Method)
	require.Equal(t, "parent", fc.ParentName)
}
