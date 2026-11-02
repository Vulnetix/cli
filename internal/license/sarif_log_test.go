package license

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildLog(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"),
		[]byte("{\n  \"dependencies\": {\n    \"gpl-lib\": \"1.0.0\"\n  }\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg := PackageLicense{PackageName: "gpl-lib", PackageVersion: "1.0.0", Ecosystem: "npm", SourceFile: "package.json"}
	res := &AnalysisResult{
		Packages: []PackageLicense{pkg},
		Findings: []Finding{{ID: "f1", Title: "Strong copyleft", Description: "gpl-lib is GPL-3.0", Severity: "high", Package: pkg, Category: "copyleft"}},
	}
	log := BuildLog(res, dir, "test")
	run := log.Runs[0]
	if run.AutomationDetails == nil || run.AutomationDetails.ID != "vulnetix/license/" {
		t.Fatalf("category %+v", run.AutomationDetails)
	}
	if run.Tool.Driver.Rules[0].Properties["security-severity"] != "8.0" {
		t.Fatalf("rule %+v", run.Tool.Driver.Rules[0])
	}
	r := run.Results[0]
	if len(r.Locations) != 1 || r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "package.json" || r.Locations[0].PhysicalLocation.Region.StartLine != 3 {
		t.Fatalf("location %+v", r.Locations)
	}
	if r.PartialFingerprints["primaryLocationLineHash"] == "" {
		t.Fatal("no fingerprint")
	}
}
