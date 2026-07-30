package cmd

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/internal/license"
	"github.com/vulnetix/cli/v3/internal/memory"
	"github.com/vulnetix/cli/v3/internal/scan"
)

// licensedFixture mirrors what license.DetectLicenses produces: the SPDX id plus
// the resolved catalogue Record whose category the evaluator reads.
func licensedFixture() []license.PackageLicense {
	return []license.PackageLicense{
		{PackageName: "left-pad", PackageVersion: "1.3.0", Ecosystem: "npm", Scope: scan.ScopeProduction,
			SourceFile: "package.json", IsDirect: true, LicenseSpdxID: "MIT",
			LicenseSource: "manifest", Record: license.LookupSPDX("MIT")},
		{PackageName: "copyleft-lib", PackageVersion: "2.0.0", Ecosystem: "npm", Scope: scan.ScopeProduction,
			SourceFile: "package.json", IsDirect: true, LicenseSpdxID: "GPL-3.0-only",
			LicenseSource: "manifest", Record: license.LookupSPDX("GPL-3.0-only")},
	}
}

// findingCategories counts findings per rule category. Finding.ID embeds the
// package identity, so the category is the stable key.
func findingCategories(res *license.AnalysisResult) map[string]int {
	out := map[string]int{}
	for _, f := range res.Findings {
		out[f.Category]++
	}
	return out
}

// TestRunLicensePipelineAppliesPolicy is the guarantee that made it safe to have
// `scan` delegate here: the allow list drives the findings, so a scan that passes
// the project's policy gets the same verdict a standalone `license` run does.
func TestRunLicensePipelineAppliesPolicy(t *testing.T) {
	root := t.TempDir()

	permissive, err := runLicensePipeline(LicenseRunOptions{
		RootPath:         root,
		LicensedPackages: licensedFixture(),
		GitCtx:           &gitctx.GitContext{},
		Stderr:           io.Discard,
	})
	if err != nil {
		t.Fatalf("permissive run: %v", err)
	}

	restricted, err := runLicensePipeline(LicenseRunOptions{
		RootPath:         root,
		AllowCSV:         "MIT",
		LicensedPackages: licensedFixture(),
		GitCtx:           &gitctx.GitContext{},
		Stderr:           io.Discard,
	})
	if err != nil {
		t.Fatalf("restricted run: %v", err)
	}

	permissiveIDs := findingCategories(permissive.Result)
	restrictedIDs := findingCategories(restricted.Result)
	if permissiveIDs["not-in-allowlist"] != 0 {
		t.Errorf("no allow list must not produce allow-list findings: %v", permissiveIDs)
	}
	if restrictedIDs["not-in-allowlist"] == 0 {
		t.Errorf("allow list MIT must flag GPL-3.0-only: %v", restrictedIDs)
	}
	// The CycloneDX projection follows the findings.
	if len(restricted.FindingVulnerabilities) < len(permissive.FindingVulnerabilities) {
		t.Errorf("restricted policy produced fewer CDX entries (%d) than permissive (%d)",
			len(restricted.FindingVulnerabilities), len(permissive.FindingVulnerabilities))
	}
}

func TestRunLicensePipelineRejectsUnknownMode(t *testing.T) {
	_, err := runLicensePipeline(LicenseRunOptions{
		RootPath:         t.TempDir(),
		Mode:             "nope",
		LicensedPackages: licensedFixture(),
		GitCtx:           &gitctx.GitContext{},
		Stderr:           io.Discard,
	})
	if err == nil {
		t.Fatal("expected an error for an unknown mode")
	}
}

func TestRunLicensePipelineDefaultsToInclusiveMode(t *testing.T) {
	run, err := runLicensePipeline(LicenseRunOptions{
		RootPath:         t.TempDir(),
		LicensedPackages: licensedFixture(),
		GitCtx:           &gitctx.GitContext{},
		Stderr:           io.Discard,
	})
	if err != nil {
		t.Fatal(err)
	}
	if run.Result.Mode != "inclusive" {
		t.Fatalf("mode = %q, want inclusive", run.Result.Mode)
	}
}

// TestRunLicensePipelineReusesDetection covers the scan path: licenses are
// resolved once, before the /v2/cli.sca round-trip, and the evaluation must not
// redo the work (or disagree with what was sent to the API).
func TestRunLicensePipelineReusesDetection(t *testing.T) {
	fixture := licensedFixture()
	run, err := runLicensePipeline(LicenseRunOptions{
		RootPath:         t.TempDir(),
		LicensedPackages: fixture,
		Stderr:           io.Discard,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(run.LicensedPackages) != len(fixture) {
		t.Fatalf("LicensedPackages = %d entries, want the %d passed in", len(run.LicensedPackages), len(fixture))
	}
	ids := run.LicenseSpdxIDByPackage()
	if ids["left-pad@1.3.0"] != "MIT" || ids["copyleft-lib@2.0.0"] != "GPL-3.0-only" {
		t.Fatalf("LicenseSpdxIDByPackage = %v", ids)
	}
}

// TestRunLicensePipelineRecordsMemory pins the memory contract both callers rely
// on: findings are recorded, and the VEX entries stay separate from the findings
// so the scan pipeline can feed them through ApplyVEXAnalysis.
func TestRunLicensePipelineRecordsMemory(t *testing.T) {
	root := t.TempDir()
	mem := &memory.Memory{Version: "1"}

	run, err := runLicensePipeline(LicenseRunOptions{
		RootPath:         root,
		AllowCSV:         "MIT",
		LicensedPackages: licensedFixture(),
		Memory:           mem,
		GitCtx:           &gitctx.GitContext{},
		Stderr:           io.Discard,
	})
	if err != nil {
		t.Fatal(err)
	}
	combined := run.CDXVulnerabilities()
	if len(combined) != len(run.FindingVulnerabilities)+len(run.VEXVulnerabilities) {
		t.Fatalf("CDXVulnerabilities() = %d, want findings(%d)+vex(%d)",
			len(combined), len(run.FindingVulnerabilities), len(run.VEXVulnerabilities))
	}
	if len(mem.Findings) == 0 {
		t.Fatal("license findings were not recorded into memory")
	}
	// A first run records findings but transitions nothing, so there is no VEX
	// to emit yet.
	if len(run.StateChanges) != 0 {
		t.Errorf("first run produced state changes: %+v", run.StateChanges)
	}
	if len(run.VEXVulnerabilities) != 0 {
		t.Errorf("first run produced VEX entries: %+v", run.VEXVulnerabilities)
	}

	// Second run with the offending package gone: the finding must resolve, and
	// the resolution must surface as a state change plus a VEX attestation that
	// the caller can feed into the BOM.
	remaining := licensedFixture()[:1] // MIT only, and MIT is allowed
	second, err := runLicensePipeline(LicenseRunOptions{
		RootPath:         root,
		AllowCSV:         "MIT",
		LicensedPackages: remaining,
		Memory:           mem,
		GitCtx:           &gitctx.GitContext{},
		Stderr:           io.Discard,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.StateChanges) == 0 {
		t.Error("expected a resolution state change once the finding disappeared")
	}
	if len(second.VEXVulnerabilities) == 0 {
		t.Error("expected VEX attestations for the resolved finding")
	}
	if len(second.FindingVulnerabilities) != 0 {
		t.Errorf("no open findings expected, got %d", len(second.FindingVulnerabilities))
	}
}

func TestLicenseAllowListFileWinsOverCSV(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.yaml")
	if err := os.WriteFile(path, []byte("licenses:\n  - Apache-2.0\n  - BSD-3-Clause\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	fromFile, err := licenseAllowList("MIT", path)
	if err != nil {
		t.Fatal(err)
	}
	if len(fromFile) != 2 || fromFile[0] != "Apache-2.0" {
		t.Fatalf("allow file = %v, want the file's entries", fromFile)
	}

	fromCSV, err := licenseAllowList("MIT,ISC", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(fromCSV) != 2 {
		t.Fatalf("allow CSV = %v, want 2 entries", fromCSV)
	}

	if none, err := licenseAllowList("", ""); err != nil || none != nil {
		t.Fatalf("no policy = %v, %v; want nil, nil", none, err)
	}

	if _, err := licenseAllowList("", filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("expected an error for a missing allow file")
	}
}

// TestScanFamilyRegistersLicensePolicyFlags stops the delegation from silently
// regressing: if these flags disappear from the scan family, `scan` falls back to
// a permissive default policy without telling anyone.
func TestScanFamilyRegistersLicensePolicyFlags(t *testing.T) {
	for _, cmd := range []struct {
		name string
		want bool
	}{
		{"scan", true},
		{"sca", true},
		{"sast", true},
	} {
		target, _, err := rootCmd.Find([]string{cmd.name})
		if err != nil {
			t.Fatalf("finding %s: %v", cmd.name, err)
		}
		for _, flag := range []string{"allow", "allow-file", "license-mode"} {
			if target.Flags().Lookup(flag) == nil {
				t.Errorf("%s is missing --%s", cmd.name, flag)
			}
		}
		if f := target.Flags().Lookup("license-mode"); f != nil && f.DefValue != "inclusive" {
			t.Errorf("%s --license-mode default = %q, want inclusive", cmd.name, f.DefValue)
		}
	}
}
