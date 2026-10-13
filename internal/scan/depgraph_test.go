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

// Two direct dependencies reaching the target at the same depth used to give a
// different "via" on every run, because the search was seeded by ranging over a map.
// The same scan then named requests on one run and httpx on the next.
func TestFindPathIsDeterministicAmongEqualChains(t *testing.T) {
	build := func() *DepGraph {
		return &DepGraph{
			DirectDeps: map[string]ScopedPackage{
				"requests": {Name: "requests"},
				"httpx":    {Name: "httpx"},
				"aiohttp":  {Name: "aiohttp"},
			},
			Edges: map[string][]string{
				"requests": {"certifi"},
				"httpx":    {"certifi"},
				"aiohttp":  {"certifi"},
			},
		}
	}
	want := []string{"aiohttp", "certifi"} // alphabetical among equals
	for i := 0; i < 200; i++ {
		require.Equal(t, want, build().FindPath("certifi"), "iteration %d", i)
	}
}
