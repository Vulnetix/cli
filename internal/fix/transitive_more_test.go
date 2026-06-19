package fix

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// applyTransitiveRecommendation + commandFor must install the PARENT at its
// resolved version (ParentTarget), never the child's safe version (TargetVer).
func TestParentUpgradeCommandUsesParentTarget(t *testing.T) {
	fc := &FixCandidate{PackageName: "body-parser", Ecosystem: "npm", SourceFile: "package.json", TargetVer: "1.20.3"}
	require.True(t, applyTransitiveRecommendation(fc, &vdb.CliTransitiveFix{
		Method: "parent-upgrade", ParentName: "express", ParentTarget: "4.20.0", ChildTarget: "1.20.3",
	}))
	require.Contains(t, fc.Command, "express")
	require.Contains(t, fc.Command, "4.20.0")
	require.NotContains(t, fc.Command, "express@1.20.3") // never the child version on the parent

	// cargo parent-upgrade likewise targets the parent version.
	cargo := FixCandidate{PackageName: "child", Ecosystem: "cargo", SourceFile: "Cargo.toml",
		Method: MethodParentUpgrade, ParentName: "parent", ParentTarget: "2.0.0", TargetVer: "1.5.0"}
	require.Contains(t, commandFor(cargo, cargo.TargetVer), "cargo update -p parent --precise 2.0.0")
}

// A parent-upgrade whose parent is also directly bumped must rise to the higher
// (direct-bump) version so it doesn't undershoot the parent's own fix.
func TestReconcileParentUpgradeWithDirectBump(t *testing.T) {
	out := []FixCandidate{
		{PackageName: "express", Ecosystem: "npm", SourceFile: "package.json", Method: MethodDirectBump, TargetVer: "4.22.2"},
		{PackageName: "body-parser", Ecosystem: "npm", SourceFile: "package.json", Method: MethodParentUpgrade, ParentName: "express", ParentTarget: "4.20.0", TargetVer: "1.20.3"},
	}
	reconcileParentUpgrades(out)
	require.Equal(t, "4.22.2", out[1].ParentTarget, "parent-upgrade must rise to the direct-bump's higher version")
	require.Contains(t, out[1].Command, "4.22.2")

	// No direct bump of the parent → parent-upgrade target unchanged.
	out2 := []FixCandidate{
		{PackageName: "child", Ecosystem: "npm", SourceFile: "package.json", Method: MethodParentUpgrade, ParentName: "parent", ParentTarget: "2.1.0", TargetVer: "9.9.9"},
	}
	reconcileParentUpgrades(out2)
	require.Equal(t, "2.1.0", out2[0].ParentTarget)
}

// The server-resolved parent-upgrade is preferred over a local override.
func TestApplyTransitiveRecommendationParentUpgrade(t *testing.T) {
	fc := &FixCandidate{PackageName: "body-parser", Ecosystem: "npm", SourceFile: "package.json", TargetVer: "1.20.1"}
	rec := &vdb.CliTransitiveFix{
		Method: "parent-upgrade", ParentName: "express", ParentTarget: "4.18.2",
		ChildName: "body-parser", ChildTarget: "1.20.1", Ecosystem: "npm",
		Reason: "upgrade express",
	}
	require.True(t, applyTransitiveRecommendation(fc, rec))
	require.Equal(t, MethodParentUpgrade, fc.Method)
	require.Equal(t, "express", fc.ParentName)
	require.Equal(t, "4.18.2", fc.ParentTarget)
	require.Contains(t, fc.Command, "express")

	// No recommendation (or non-parent-upgrade) → caller falls back to override.
	require.False(t, applyTransitiveRecommendation(fc, nil))
	require.False(t, applyTransitiveRecommendation(fc, &vdb.CliTransitiveFix{Method: "override"}))
}

func TestResolveTransitiveFallsToOverrideForNpmFamily(t *testing.T) {
	fc := &FixCandidate{
		PackageName: "nested-vuln",
		Ecosystem:   "npm",
		TargetVer:   "4.17.21",
	}
	resolveTransitive(fc, nil)
	require.False(t, fc.Skipped, "npm-family transitive should be fixable via override")
	require.Equal(t, MethodOverride, fc.Method)
	require.NotEmpty(t, fc.Reason)
}

// Cross-ecosystem: previously non-npm transitive deps were silently Skipped.
// Now every supported ecosystem resolves to a deterministic override/pin.
func TestResolveTransitiveOverridesEveryEcosystem(t *testing.T) {
	cases := []struct {
		ecosystem string
		source    string
		wantCmd   string // substring the install command must contain
	}{
		{"cargo", "Cargo.toml", "cargo update -p some-crate --precise 1.2.3"},
		{"golang", "go.mod", "go get example.com/m@v1.2.3 && go mod tidy"},
		{"pypi", "requirements.txt", "pip install -r requirements.txt"},
		{"maven", "pom.xml", "dependency:resolve"},
		{"composer", "composer.json", "composer update org/pkg"},
		{"rubygems", "Gemfile", "bundle update some-gem"},
	}
	for _, tc := range cases {
		t.Run(tc.ecosystem, func(t *testing.T) {
			name := "some-crate"
			switch tc.ecosystem {
			case "golang":
				name = "example.com/m"
			case "composer":
				name = "org/pkg"
			case "rubygems":
				name = "some-gem"
			}
			fc := &FixCandidate{PackageName: name, Ecosystem: tc.ecosystem, SourceFile: tc.source, TargetVer: "1.2.3"}
			resolveTransitive(fc, nil)
			require.False(t, fc.Skipped, "%s transitive should now be fixable via override", tc.ecosystem)
			require.Equal(t, MethodOverride, fc.Method)
			require.NotEmpty(t, fc.Reason)
			require.Contains(t, fc.Command, tc.wantCmd)
		})
	}
}
