package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/vulnetix/cli/v4/internal/cdx"
	"github.com/vulnetix/cli/v4/internal/scan"
	"github.com/vulnetix/cli/v4/internal/vex"
	"github.com/vulnetix/cli/v4/pkg/vdb"
)

func orgTestBOM() *cdx.BOM {
	return &cdx.BOM{BOMFormat: "CycloneDX", SpecVersion: "1.6", Version: 1,
		Components: []cdx.Component{
			{Type: "library", BOMRef: "pkg:npm/lodash@4.17.20", Name: "lodash", Version: "4.17.20", Purl: "pkg:npm/lodash@4.17.20"},
			{Type: "library", BOMRef: "pkg:npm/express@4.18.2", Name: "express", Version: "4.18.2", Purl: "pkg:npm/express@4.18.2"},
		},
		Vulnerabilities: []cdx.Vulnerability{
			{ID: "CVE-1", Affects: []cdx.Affect{{Ref: "pkg:npm/lodash@4.17.20"}}},
			{ID: "CVE-1", Affects: []cdx.Affect{{Ref: "pkg:npm/express@4.18.2"}}},
			{ID: "CVE-2", Affects: []cdx.Affect{{Ref: "pkg:npm/express@4.18.2"}}},
		}}
}

// The whole pass: a valid statement closes its package and not the same CVE in
// another, and an earlier scan's verdict leaves its finding open and is reported.
func TestRunVEXPassChecksOrgStatements(t *testing.T) {
	bom := orgTestBOM()
	pass, err := runVEXPass(VEXPassOptions{BOM: bom, Repo: "acme/app", Org: []vex.OrgStatement{
		{VulnID: "CVE-1", Status: "not_affected", Justification: "inline_mitigations_already_exist", Repository: "acme/app",
			Tooling: "Example VEX", DocumentID: "urn:one", Products: []string{"pkg:npm/lodash@4.17.20"}},
		{VulnID: "CVE-2", Status: "not_affected", Justification: "vulnerable_code_not_present", Repository: "acme/app",
			Tooling: "vulnetix-cli-finalize", DocumentID: "urn:two", Products: []string{"pkg:npm/express@4.18.2"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if pass.Result.Suppressed != 1 || pass.Result.Effective != 2 {
		t.Fatalf("suppressed %d effective %d, want 1 and 2", pass.Result.Suppressed, pass.Result.Effective)
	}
	if len(pass.OrgHeld) != 1 || pass.OrgHeld[0].VulnID != "CVE-2" || pass.OrgHeld[0].Reason != vex.HoldAbsenceInferred {
		t.Fatalf("held = %+v", pass.OrgHeld)
	}

	vulns := []scan.EnrichedVuln{
		{VulnFinding: scan.VulnFinding{CveID: "CVE-1", PackageName: "lodash", PackageVer: "4.17.20"}},
		{VulnFinding: scan.VulnFinding{CveID: "CVE-1", PackageName: "express", PackageVer: "4.18.2"}},
		{VulnFinding: scan.VulnFinding{CveID: "CVE-2", PackageName: "express", PackageVer: "4.18.2"}},
	}
	got := filterVEXSuppressed(vulns, pass)
	if len(got) != 2 {
		t.Fatalf("gate input has %d findings, want 2: %+v", len(got), got)
	}
	for _, v := range got {
		if v.CveID == "CVE-1" && v.PackageName == "lodash" {
			t.Error("the closed finding reached the gates")
		}
	}

	var out bytes.Buffer
	writeOrgVEXHeld(&out, pass)
	if s := out.String(); !strings.Contains(s, "1 finding(s) stay open") || !strings.Contains(s, "1 an earlier scan recorded as gone") || !strings.Contains(s, "CVE-2 pkg:npm/express@4.18.2") {
		t.Errorf("report = %q", s)
	}
}

func TestFilterVEXSuppressedMatchesEachEcosystemsSpelling(t *testing.T) {
	cases := []struct{ purl, name, version string }{
		{"pkg:npm/lodash@4.17.20", "lodash", "4.17.20"},
		{"pkg:npm/%40babel/core@7.0.0", "@babel/core", "7.0.0"},
		{"pkg:golang/github.com/foo/bar@v1.2.3?type=module", "github.com/foo/bar", "v1.2.3"},
		{"pkg:maven/org.apache/commons@1.0", "org.apache:commons", "1.0"},
		{"pkg:composer/vendor/pkg@2.0", "vendor/pkg", "2.0"},
	}
	for _, tc := range cases {
		pass := &VEXPassResult{Result: &vex.Result{Suppressed: 1, Applied: []vex.AppliedStatement{
			{VulnID: "CVE-1", Purl: tc.purl, Suppressed: true},
		}}}
		vulns := []scan.EnrichedVuln{
			{VulnFinding: scan.VulnFinding{CveID: "CVE-1", PackageName: tc.name, PackageVer: tc.version}},
			{VulnFinding: scan.VulnFinding{CveID: "CVE-1", PackageName: "unrelated", PackageVer: tc.version}},
		}
		got := filterVEXSuppressed(vulns, pass)
		if len(got) != 1 || got[0].PackageName != "unrelated" {
			t.Errorf("%s: kept %+v", tc.purl, got)
		}
	}
}

// An entry with no purl has only its id, and that still closes it.
func TestFilterVEXSuppressedWithNoPurlUsesTheID(t *testing.T) {
	pass := &VEXPassResult{Result: &vex.Result{Suppressed: 1, Applied: []vex.AppliedStatement{
		{VulnID: "CVE-1", Suppressed: true},
	}}}
	vulns := []scan.EnrichedVuln{{VulnFinding: scan.VulnFinding{CveID: "CVE-1", PackageName: "a", PackageVer: "1"}}}
	if got := filterVEXSuppressed(vulns, pass); len(got) != 0 {
		t.Errorf("kept %+v", got)
	}
}

// A finding that does not name its package is treated as before: the id decides.
func TestFilterVEXSuppressedFallsBackToTheID(t *testing.T) {
	pass := &VEXPassResult{Result: &vex.Result{Suppressed: 1, Applied: []vex.AppliedStatement{
		{VulnID: "CVE-1", Purl: "pkg:npm/a@1", Suppressed: true},
	}}}
	if got := filterVEXSuppressed([]scan.EnrichedVuln{{VulnFinding: scan.VulnFinding{CveID: "CVE-1"}}}, pass); len(got) != 0 {
		t.Errorf("kept %+v", got)
	}
}

func TestReadOrgVEXChunksAndFlattens(t *testing.T) {
	ids := make([]string, orgVEXChunk+3)
	for i := range ids {
		ids[i] = fmt.Sprintf("CVE-%d", i)
	}
	var calls []int
	got := readOrgVEX(func(chunk []string) (map[string][]vdb.CliOrgVexStatement, error) {
		calls = append(calls, len(chunk))
		return map[string][]vdb.CliOrgVexStatement{chunk[0]: {{Status: "fixed", RepositoryFullName: "acme/app", Tooling: "x", Products: []string{"pkg:npm/a@1"}}}}, nil
	}, ids, nil)
	if len(calls) != 2 || calls[0] != orgVEXChunk || calls[1] != 3 {
		t.Fatalf("calls = %v", calls)
	}
	if len(got) != 2 || got[0].Repository != "acme/app" || got[0].Products[0] != "pkg:npm/a@1" {
		t.Fatalf("statements = %+v", got)
	}
}

// A statement that could not be read closes nothing, and the run says so.
func TestReadOrgVEXFailureClosesNothing(t *testing.T) {
	var notes bytes.Buffer
	got := readOrgVEX(func([]string) (map[string][]vdb.CliOrgVexStatement, error) {
		return nil, errors.New("boom")
	}, []string{"CVE-1"}, &notes)
	if len(got) != 0 || !strings.Contains(notes.String(), "could not read") {
		t.Fatalf("got %+v, notes %q", got, notes.String())
	}
}

func TestReadOrgVEXSaysWhenAReplyIsFull(t *testing.T) {
	rows := make([]vdb.CliOrgVexStatement, orgVEXReplyCap)
	var notes bytes.Buffer
	readOrgVEX(func([]string) (map[string][]vdb.CliOrgVexStatement, error) {
		return map[string][]vdb.CliOrgVexStatement{"CVE-1": rows}, nil
	}, []string{"CVE-1"}, &notes)
	if !strings.Contains(notes.String(), "some were not checked") {
		t.Fatalf("notes %q", notes.String())
	}
}
