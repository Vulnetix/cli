package license

import (
	"sort"
	"strings"
	"testing"
)

func evaluateIDs(t *testing.T, pkgs []PackageLicense) []string {
	t.Helper()
	result := Evaluate(pkgs, EvalConfig{Mode: "inclusive"})
	ids := make([]string, 0, len(result.Findings))
	for _, f := range result.Findings {
		ids = append(ids, f.ID)
	}
	sort.Strings(ids)
	return ids
}

// Finding IDs are the reconciliation key: memory resolves a finding by noticing
// its ID has left the current result set. A run-local counter would make every
// run look like a total turnover.
func TestFindingIDs_StableAcrossRuns(t *testing.T) {
	pkgs := []PackageLicense{
		{PackageName: "mystery-pkg", PackageVersion: "1.0.0", Ecosystem: "npm", LicenseSpdxID: "UNKNOWN"},
		{PackageName: "other-pkg", PackageVersion: "2.1.0", Ecosystem: "npm", LicenseSpdxID: "UNKNOWN"},
	}

	first := evaluateIDs(t, pkgs)
	second := evaluateIDs(t, pkgs)
	if len(first) == 0 {
		t.Fatal("expected at least one finding")
	}
	if strings.Join(first, ",") != strings.Join(second, ",") {
		t.Errorf("IDs differ between runs:\n  run 1: %v\n  run 2: %v", first, second)
	}

	// Order of the input must not change the IDs either — package iteration
	// order was exactly what the old counter leaked into the identifier.
	reversed := []PackageLicense{pkgs[1], pkgs[0]}
	third := evaluateIDs(t, reversed)
	if strings.Join(first, ",") != strings.Join(third, ",") {
		t.Errorf("IDs depend on package order:\n  forward: %v\n  reversed: %v", first, third)
	}
}

func TestFindingID_Shape(t *testing.T) {
	got := FindingID("copyleft-in-production", PackageLicense{
		PackageName: "Some-Pkg", PackageVersion: "4.17.21", Ecosystem: "NPM",
	})
	want := "LICENSE:copyleft-in-production:npm:some-pkg@4.17.21"
	if got != want {
		t.Errorf("FindingID = %q, want %q", got, want)
	}
}

// The same conflict discovered from either direction must yield one identifier,
// or a single conflict would be recorded (and resolved) as two findings.
func TestConflictFindingID_OrderIndependent(t *testing.T) {
	a := ConflictFindingID(LicenseConflict{
		License1: "GPL-3.0-only", License2: "Apache-2.0",
		Package1: "zeta", Package2: "alpha",
	})
	b := ConflictFindingID(LicenseConflict{
		License1: "Apache-2.0", License2: "GPL-3.0-only",
		Package1: "alpha", Package2: "zeta",
	})
	if a != b {
		t.Errorf("conflict ID depends on pair order:\n  %s\n  %s", a, b)
	}
	want := "LICENSE:license-conflict:Apache-2.0|GPL-3.0-only:alpha|zeta"
	if a != want {
		t.Errorf("ConflictFindingID = %q, want %q", a, want)
	}
}
