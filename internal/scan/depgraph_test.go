package scan

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestFindPathMemoMatchesFindPath verifies the memoised variant returns exactly
// what FindPath returns (so the introduced-paths display is unchanged) and caches
// both positive and negative results.
func TestFindPathMemoMatchesFindPath(t *testing.T) {
	g := &DepGraph{
		DirectDeps: map[string]ScopedPackage{"root": {Name: "root"}},
		Edges: map[string][]string{
			"root": {"mid"},
			"mid":  {"leaf"},
		},
	}

	// Positive: chain root -> mid -> leaf.
	want := g.FindPath("leaf")
	require.Equal(t, []string{"root", "mid", "leaf"}, want)
	require.Equal(t, want, g.FindPathMemo("leaf"))
	// Cached call returns the identical result.
	require.Equal(t, want, g.FindPathMemo("leaf"))

	// Negative: no path — cached as nil, still nil on repeat.
	require.Nil(t, g.FindPathMemo("absent"))
	require.Nil(t, g.FindPathMemo("absent"))

	// nil receiver is safe.
	var ng *DepGraph
	require.Nil(t, ng.FindPathMemo("leaf"))
}
