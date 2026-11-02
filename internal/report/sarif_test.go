package report

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildSARIFForSCA(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"),
		[]byte("{\n  \"dependencies\": {\n    \"lodash\": \"4.17.20\"\n  }\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg := func(version string) Report {
		return Report{Packages: []Package{{
			Name: "lodash", Version: version, Ecosystem: "npm", Source: "package.json", Direct: true,
			Advisories: []Advisory{{ID: "CVE-2021-23337", Severity: "high", CVSS: 7.2}},
			Fix:        Fix{Target: "4.17.21"},
		}}}
	}
	log := BuildSARIF(pkg("4.17.20"), dir, "test")
	run := log.Runs[0]
	if run.AutomationDetails == nil || run.AutomationDetails.ID != "vulnetix/sca/" {
		t.Fatalf("category %+v", run.AutomationDetails)
	}
	if len(run.Tool.Driver.Rules) != 1 || run.Tool.Driver.Rules[0].Properties["security-severity"] != "7.2" {
		t.Fatalf("rules %+v", run.Tool.Driver.Rules)
	}
	res := run.Results[0]
	if res.Locations[0].PhysicalLocation.Region.StartLine != 3 {
		t.Fatalf("line %d, want the declaring line 3", res.Locations[0].PhysicalLocation.Region.StartLine)
	}
	fp := res.PartialFingerprints["primaryLocationLineHash"]
	if fp == "" {
		t.Fatal("no fingerprint")
	}
	// A version bump that leaves the advisory open is the same alert.
	if again := BuildSARIF(pkg("4.17.19"), dir, "test").Runs[0].Results[0].PartialFingerprints["primaryLocationLineHash"]; again != fp {
		t.Fatalf("fingerprint changed with the version: %s vs %s", fp, again)
	}

	empty := BuildSARIF(Report{}, dir, "test")
	if len(empty.Runs) != 1 || empty.Runs[0].Results == nil {
		t.Fatal("a clean report must still be a run with an empty result list")
	}
}
