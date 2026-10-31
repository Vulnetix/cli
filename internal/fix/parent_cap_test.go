package fix

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// The scenario found running fix on a bun project with express 4.17.1: the
// server recommends a parent upgrade per vulnerable child, each with its own
// express version (4.22.0 for send, 4.21.2 for path-to-regexp, 4.22.3 for qs)
// and 5.1.0 for debug. Run in turn, the last install won and undid the others,
// and the 5.1.0 one ignored the major-version cap.
func TestBuildPlans_ParentUpgradesAreCappedAndReconciled(t *testing.T) {
	const pj = "package.json"
	child := func(name, ver string) scan.EnrichedVuln {
		return scan.EnrichedVuln{VulnFinding: scan.VulnFinding{
			CveID: "CVE-" + name, PackageName: name, PackageVer: ver, Ecosystem: "npm", SourceFile: "bun.lock",
		}}
	}
	vulns := []scan.EnrichedVuln{child("send", "0.17.1"), child("path-to-regexp", "0.1.7"), child("qs", "6.7.0"), child("debug", "2.6.9")}
	pkgs := []scan.ScopedPackage{
		{Name: "express", Version: "4.17.1", Ecosystem: "npm", SourceFile: "bun.lock", IsDirect: true},
		{Name: "send", Version: "0.17.1", Ecosystem: "npm", SourceFile: "bun.lock"},
		{Name: "path-to-regexp", Version: "0.1.7", Ecosystem: "npm", SourceFile: "bun.lock"},
		{Name: "qs", Version: "6.7.0", Ecosystem: "npm", SourceFile: "bun.lock"},
		{Name: "debug", Version: "2.6.9", Ecosystem: "npm", SourceFile: "bun.lock"},
	}
	groups := scan.BuildManifestGroups(map[string][]scan.ScopedPackage{
		pj:         {{Name: "express", Version: "4.17.1", VersionSpec: "4.17.1", Ecosystem: "npm", IsDirect: true}},
		"bun.lock": pkgs,
	}, map[string]string{pj: "npm", "bun.lock": "npm"})
	rec := func(name, ver, childTarget, parentTarget string) vdb.CliPackageInsight {
		return vdb.CliPackageInsight{
			Purl: "pkg:npm/" + name + "@" + ver, Name: name, Version: ver, Ecosystem: "npm",
			TransitiveFix: &vdb.CliTransitiveFix{Method: "parent-upgrade", ParentName: "express", ParentTarget: parentTarget, ChildName: name, ChildTarget: childTarget},
		}
	}
	insights := []vdb.CliPackageInsight{
		rec("send", "0.17.1", "0.19.1", "4.22.0"),
		rec("path-to-regexp", "0.1.7", "0.1.12", "4.21.2"),
		rec("qs", "6.7.0", "6.16.2", "4.22.3"),
		rec("debug", "2.6.9", "4.4.3", "5.1.0"),
	}

	batch := BuildPlans(vulns, pkgs, groups, insights, Options{Strategy: StrategyStable, MaxMajorBump: 0})
	byName := map[string]FixCandidate{}
	for _, p := range batch.Plans {
		byName[p.PackageName] = p
	}

	for _, name := range []string{"send", "path-to-regexp", "qs"} {
		p := byName[name]
		require.Equal(t, MethodParentUpgrade, p.Method, name)
		require.False(t, p.Skipped, name)
		require.Equal(t, "4.22.3", p.ParentTarget, "%s: every upgrade of express installs the highest", name)
		require.Empty(t, p.SkipReason, "%s: a planned fix carries no skip reason", name)
	}
	require.Contains(t, byName["send"].Reason, "raised to express 4.22.3")

	d := byName["debug"]
	require.NotEqual(t, "5.1.0", d.ParentTarget, "express 5 crosses the major-version cap")
	if d.Skipped {
		require.Contains(t, d.SkipReason, "express 5.1.0")
	}
}

func TestParentUpgradeOverCap(t *testing.T) {
	groups := scan.BuildManifestGroups(map[string][]scan.ScopedPackage{
		"package.json": {{Name: "express", Version: "4.17.1", Ecosystem: "npm", IsDirect: true}},
	}, map[string]string{"package.json": "npm"})
	fc := FixCandidate{Method: MethodParentUpgrade, ParentName: "express", ParentTarget: "5.1.0", SourceFile: "./package.json"}
	require.Contains(t, parentUpgradeOverCap(fc, groups, 0), "major-version cap is 0")
	require.Empty(t, parentUpgradeOverCap(fc, groups, 1), "a cap of 1 allows 4 -> 5")
	require.Empty(t, parentUpgradeOverCap(fc, groups, -1), "a negative cap lifts it")
	fc.ParentTarget = "4.22.3"
	require.Empty(t, parentUpgradeOverCap(fc, groups, 0))
	fc.ParentName = "unknown"
	fc.ParentTarget = "9.0.0"
	require.Empty(t, parentUpgradeOverCap(fc, groups, 0), "an unknown current version is not judged")
}
