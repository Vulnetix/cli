package license

import "testing"

func TestEvaluate_UnknownLicense(t *testing.T) {
	pkgs := []PackageLicense{
		{PackageName: "mystery-pkg", PackageVersion: "1.0.0", Ecosystem: "npm", LicenseSpdxID: "UNKNOWN"},
	}
	result := Evaluate(pkgs, EvalConfig{Mode: "inclusive"})
	if result.Summary.Unknown != 1 {
		t.Errorf("expected 1 unknown, got %d", result.Summary.Unknown)
	}
	found := false
	for _, f := range result.Findings {
		if f.Category == "unknown-license" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected unknown-license finding")
	}
}

func TestEvaluate_DeprecatedLicense(t *testing.T) {
	rec := LookupSPDX("GPL-2.0") // deprecated ID
	if rec == nil {
		t.Skip("GPL-2.0 not in SPDX database")
	}
	if !rec.IsDeprecated {
		t.Skip("GPL-2.0 is not marked as deprecated in this version of SPDX")
	}
	pkgs := []PackageLicense{
		{PackageName: "old-pkg", PackageVersion: "1.0.0", Ecosystem: "npm", LicenseSpdxID: "GPL-2.0", Record: rec},
	}
	result := Evaluate(pkgs, EvalConfig{Mode: "inclusive"})
	found := false
	for _, f := range result.Findings {
		if f.Category == "deprecated-license" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected deprecated-license finding")
	}
}

func TestEvaluate_AllowList(t *testing.T) {
	mitRec := LookupSPDX("MIT")
	apacheRec := LookupSPDX("Apache-2.0")
	pkgs := []PackageLicense{
		{PackageName: "pkg-a", PackageVersion: "1.0.0", Ecosystem: "npm", LicenseSpdxID: "MIT", Record: mitRec},
		{PackageName: "pkg-b", PackageVersion: "2.0.0", Ecosystem: "npm", LicenseSpdxID: "Apache-2.0", Record: apacheRec},
	}
	result := Evaluate(pkgs, EvalConfig{
		Mode:            "inclusive",
		AllowedLicenses: []string{"MIT"},
	})
	notAllowed := 0
	for _, f := range result.Findings {
		if f.Category == "not-in-allowlist" {
			notAllowed++
		}
	}
	if notAllowed != 1 {
		t.Errorf("expected 1 not-in-allowlist finding, got %d", notAllowed)
	}
}

func TestEvaluate_ConflictDetection(t *testing.T) {
	gplRec := LookupSPDX("GPL-3.0-only")
	buslRec := LookupSPDX("BUSL-1.1")
	if gplRec == nil || buslRec == nil {
		t.Skip("missing SPDX records")
	}
	pkgs := []PackageLicense{
		{PackageName: "gpl-pkg", PackageVersion: "1.0.0", Ecosystem: "npm", LicenseSpdxID: "GPL-3.0-only", Record: gplRec},
		{PackageName: "busl-pkg", PackageVersion: "1.0.0", Ecosystem: "npm", LicenseSpdxID: "BUSL-1.1", Record: buslRec},
	}
	result := Evaluate(pkgs, EvalConfig{Mode: "inclusive"})
	if result.Summary.ConflictCount == 0 {
		t.Error("expected at least 1 conflict between GPL-3.0-only and BUSL-1.1")
	}
}

func TestEvaluate_CopyleftInProduction(t *testing.T) {
	gplRec := LookupSPDX("GPL-3.0-only")
	if gplRec == nil {
		t.Skip("GPL-3.0-only not in SPDX database")
	}
	pkgs := []PackageLicense{
		{PackageName: "gpl-lib", PackageVersion: "1.0.0", Ecosystem: "npm", Scope: "production", LicenseSpdxID: "GPL-3.0-only", Record: gplRec},
	}
	result := Evaluate(pkgs, EvalConfig{Mode: "inclusive"})
	found := false
	for _, f := range result.Findings {
		if f.Category == "copyleft-in-production" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected copyleft-in-production finding")
	}
}

func TestCountFindingsAtOrAbove(t *testing.T) {
	findings := []Finding{
		{Severity: "critical"},
		{Severity: "high"},
		{Severity: "medium"},
		{Severity: "low"},
	}
	if got := CountFindingsAtOrAbove(findings, "high"); got != 2 {
		t.Errorf("CountFindingsAtOrAbove(high) = %d, want 2", got)
	}
	if got := CountFindingsAtOrAbove(findings, "medium"); got != 3 {
		t.Errorf("CountFindingsAtOrAbove(medium) = %d, want 3", got)
	}
	if got := CountFindingsAtOrAbove(findings, "critical"); got != 1 {
		t.Errorf("CountFindingsAtOrAbove(critical) = %d, want 1", got)
	}
}

func TestEvaluate_IndividualMode(t *testing.T) {
	mitRec := LookupSPDX("MIT")
	gplRec := LookupSPDX("GPL-3.0-only")
	buslRec := LookupSPDX("BUSL-1.1")
	if mitRec == nil || gplRec == nil || buslRec == nil {
		t.Skip("missing SPDX records")
	}
	pkgs := []PackageLicense{
		{PackageName: "a", Ecosystem: "npm", LicenseSpdxID: "MIT", Record: mitRec, SourceFile: "a/package.json"},
		{PackageName: "b", Ecosystem: "npm", LicenseSpdxID: "GPL-3.0-only", Record: gplRec, SourceFile: "b/package.json"},
		{PackageName: "c", Ecosystem: "npm", LicenseSpdxID: "BUSL-1.1", Record: buslRec, SourceFile: "b/package.json"},
	}
	result := Evaluate(pkgs, EvalConfig{Mode: "individual"})
	// Conflict should only be between GPL-3.0-only and BUSL-1.1 in b/package.json,
	// not between MIT (in a/) and others.
	if result.Summary.ConflictCount == 0 {
		t.Error("expected at least 1 conflict in individual mode")
	}
}
