package fix

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulnetix/cli/v3/internal/scan"
)

func TestEditableManifestForMapsLockToSiblingManifest(t *testing.T) {
	groups := []scan.ManifestGroup{{Files: []string{"package.json", "package-lock.json"}}}
	require.Equal(t, "package.json", editableManifestFor("package-lock.json", groups))
	require.Equal(t, "package.json", editableManifestFor("package.json", groups))
}

func TestEditableManifestForLeavesLockWhenNoManifest(t *testing.T) {
	groups := []scan.ManifestGroup{{Files: []string{"package-lock.json"}}}
	// No sibling manifest to retarget to: keep the original.
	require.Equal(t, "package-lock.json", editableManifestFor("package-lock.json", groups))
}

func TestIsLockfile(t *testing.T) {
	require.True(t, isLockfile("package-lock.json"))
	require.True(t, isLockfile("a/b/yarn.lock"))
	require.False(t, isLockfile("package.json"))
	require.False(t, isLockfile("pom.xml"))
}

func TestBuildPlansFallsBackToLegacyRemediationFixVersion(t *testing.T) {
	batch := BuildPlans([]scan.EnrichedVuln{{
		VulnFinding: scan.VulnFinding{
			CveID:       "CVE-2024-0001",
			PackageName: "lodash",
			PackageVer:  "4.17.20",
			Ecosystem:   "npm",
			SourceFile:  "package.json",
		},
		Remediation: &scan.RemediationInfo{FixVersion: "4.17.21"},
	}}, []scan.ScopedPackage{{
		Name:       "lodash",
		Version:    "4.17.20",
		Ecosystem:  "npm",
		SourceFile: "package.json",
		IsDirect:   true,
	}}, nil, nil, Options{Strategy: StrategySafest, MaxMajorBump: 0})

	require.Len(t, batch.Plans, 1)
	require.False(t, batch.Plans[0].Skipped)
	require.Equal(t, "4.17.21", batch.Plans[0].TargetVer)
	require.Contains(t, batch.Plans[0].Reason, "legacy remediation")
}

func TestRemediationFallbackTargetHonorsMajorGuardrail(t *testing.T) {
	target, decision := remediationFallbackTarget("1.0.0", []string{"2.0.0"}, 0)

	require.Empty(t, target)
	require.True(t, decision.Skipped)
}
