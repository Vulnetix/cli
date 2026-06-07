package fix

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveTransitiveFallsToOverrideForNpmFamily(t *testing.T) {
	fc := &FixCandidate{
		PackageName: "nested-vuln",
		Ecosystem:   "npm",
		TargetVer:   "4.17.21",
	}
	resolveTransitive(fc, nil, nil)
	require.False(t, fc.Skipped, "npm-family transitive should be fixable via override")
	require.Equal(t, MethodOverride, fc.Method)
	require.NotEmpty(t, fc.Reason)
}

func TestResolveTransitiveSkipsUneditableEcosystem(t *testing.T) {
	fc := &FixCandidate{
		PackageName: "some-crate",
		Ecosystem:   "cargo",
		TargetVer:   "1.2.3",
	}
	resolveTransitive(fc, nil, nil)
	require.True(t, fc.Skipped)
	require.NotEmpty(t, fc.SkipReason)
}
