package fix

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// A Go batch with multiple fixes must collapse into ONE `go get … && go mod tidy`
// (one resolution), not N per-fix tidies.
func TestBatchInstallCommandGoCollapses(t *testing.T) {
	b := FixBatch{
		Ecosystem:  "golang",
		SourceFile: "go.mod",
		Plans: []FixCandidate{
			{PackageName: "golang.org/x/net", Ecosystem: "golang", TargetVer: "0.38.0", Method: MethodDirectBump},
			{PackageName: "golang.org/x/crypto", Ecosystem: "golang", TargetVer: "0.36.0", Method: MethodOverride},
			{PackageName: "child", Ecosystem: "golang", TargetVer: "1.2.3", Method: MethodParentUpgrade, ParentName: "parent", ParentTarget: "2.0.0"},
			{PackageName: "skipped", Ecosystem: "golang", Skipped: true, TargetVer: "9.9.9"},
		},
	}
	cmd, ok := batchInstallCommand(b)
	require.True(t, ok)
	// One tidy, parent uses ParentTarget, skipped excluded.
	require.Equal(t, 1, strings.Count(cmd, "go mod tidy"))
	require.Equal(t, 1, strings.Count(cmd, "go get "))
	require.Contains(t, cmd, "golang.org/x/net@v0.38.0")
	require.Contains(t, cmd, "golang.org/x/crypto@v0.36.0")
	require.Contains(t, cmd, "parent@v2.0.0")
	require.NotContains(t, cmd, "child@") // parent-upgrade installs the parent, not the child
	require.NotContains(t, cmd, "skipped")
	require.True(t, strings.HasSuffix(cmd, "&& go mod tidy"))
}

func TestBatchInstallCommandNonGoUnchanged(t *testing.T) {
	for _, eco := range []string{"npm", "pypi", "maven", "cargo", "composer", "rubygems"} {
		_, ok := batchInstallCommand(FixBatch{
			Ecosystem: eco,
			Plans:     []FixCandidate{{PackageName: "x", Ecosystem: eco, TargetVer: "1.0.0", Method: MethodDirectBump}},
		})
		require.False(t, ok, "%s must remain per-plan (npm/pypi already collapse elsewhere)", eco)
	}
}

func TestBatchInstallCommandEmptyWhenNoActionablePlans(t *testing.T) {
	_, ok := batchInstallCommand(FixBatch{
		Ecosystem: "golang",
		Plans:     []FixCandidate{{PackageName: "x", Ecosystem: "golang", Skipped: true, TargetVer: "1.0.0"}},
	})
	require.False(t, ok)
}
