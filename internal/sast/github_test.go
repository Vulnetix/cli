package sast

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestBuildSARIFIsGitHubCompatible(t *testing.T) {
	rule := RuleMetadata{ID: "VNX-1", Name: "sqli", Severity: "high", Kind: "sast", CWE: []int{89}, Tags: []string{"injection"}}
	f := Finding{RuleID: "VNX-1", ArtifactURI: "app.py", StartLine: 2, Severity: "high", Level: "error", Metadata: &rule}
	log := BuildSARIF([]Finding{f}, []RuleMetadata{rule}, "test")

	run := log.Runs[0]
	if run.AutomationDetails == nil || run.AutomationDetails.ID != "vulnetix/sast/" {
		t.Fatalf("automationDetails = %+v", run.AutomationDetails)
	}
	props := run.Tool.Driver.Rules[0].Properties
	if props["security-severity"] != "8.0" {
		t.Fatalf("security-severity = %v", props["security-severity"])
	}
	want := []string{"injection", "security", "external/cwe/cwe-89"}
	if !reflect.DeepEqual(props["tags"], want) {
		t.Fatalf("tags = %v, want %v", props["tags"], want)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("x = 2\nx = 1\nprint(x)\nx = 3\nprint(x)\nx = 4\nprint(x)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	AddLineHashes(log, dir)
	if got := log.Runs[0].Results[0].PartialFingerprints["primaryLocationLineHash"]; got != "bb609acbe9138d60:1" {
		t.Fatalf("primaryLocationLineHash = %q", got)
	}
}

func TestBuildSARIFMixedKindsHasNoCategory(t *testing.T) {
	a := RuleMetadata{ID: "A", Kind: "sast"}
	b := RuleMetadata{ID: "B", Kind: "secrets"}
	log := BuildSARIF([]Finding{
		{RuleID: "A", ArtifactURI: "a", Metadata: &a},
		{RuleID: "B", ArtifactURI: "b", Metadata: &b},
	}, []RuleMetadata{a, b}, "test")
	if log.Runs[0].AutomationDetails != nil {
		t.Fatalf("a mixed run claimed a category: %+v", log.Runs[0].AutomationDetails)
	}

	split := SplitByKind(log)
	if len(split) != 2 {
		t.Fatalf("split into %d logs, want 2", len(split))
	}
	for kind, want := range map[string]string{"sast": "A", "secrets": "B"} {
		l := split[kind]
		if l == nil || len(l.Runs) != 1 {
			t.Fatalf("%s: %+v", kind, l)
		}
		r := l.Runs[0]
		if r.AutomationDetails.ID != "vulnetix/"+kind+"/" {
			t.Fatalf("%s category %q", kind, r.AutomationDetails.ID)
		}
		if len(r.Results) != 1 || r.Results[0].RuleID != want || len(r.Tool.Driver.Rules) != 1 || r.Tool.Driver.Rules[0].ID != want {
			t.Fatalf("%s run = %+v", kind, r)
		}
	}
}

func TestSplitByKindContainersCategory(t *testing.T) {
	r := RuleMetadata{ID: "C", Kind: "oci"}
	log := BuildSARIF([]Finding{{RuleID: "C", ArtifactURI: "Dockerfile", Metadata: &r}}, []RuleMetadata{r}, "t")
	if got := log.Runs[0].AutomationDetails.ID; got != "vulnetix/containers/" {
		t.Fatalf("category %q", got)
	}
	if _, ok := SplitByKind(log)["containers"]; !ok {
		t.Fatal("no containers log")
	}
}

func TestPrepareForGitHubKeepsTheWorst(t *testing.T) {
	results := make([]SARIFResult, 0, MaxGitHubResultsPerRun+2)
	for i := 0; i < MaxGitHubResultsPerRun; i++ {
		results = append(results, SARIFResult{RuleID: "low", Properties: SARIFPropertyBag{"severity": "low"}})
	}
	results = append(results,
		SARIFResult{RuleID: "crit", Properties: SARIFPropertyBag{"severity": "critical"}},
		SARIFResult{RuleID: "high", Properties: SARIFPropertyBag{"severity": "high"}})
	log := &SARIFLog{Runs: []SARIFRun{{Results: results}}}
	if dropped := PrepareForGitHub(log, t.TempDir()); dropped != 2 {
		t.Fatalf("dropped %d", dropped)
	}
	got := log.Runs[0].Results
	if len(got) != MaxGitHubResultsPerRun || got[0].RuleID != "crit" || got[1].RuleID != "high" {
		t.Fatalf("kept %d, first %s %s", len(got), got[0].RuleID, got[1].RuleID)
	}
}

func TestManifestLines(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte("{\n  \"dependencies\": {\n    \"react-dom\": \"1\",\n    \"react\": \"1\"\n  }\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := NewManifestLines(dir)
	if got := m.Find("package.json", "react"); got != 4 {
		t.Fatalf("react on line %d, want 4", got)
	}
	if got := m.Find("package.json", "lodash"); got != 0 {
		t.Fatalf("lodash on line %d", got)
	}
	if !containsWord("requests==2.0", "requests") || containsWord("react-dom", "react") {
		t.Fatal("containsWord")
	}
}
