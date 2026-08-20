package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// TestJailVEXKeepsAffectedStatusWithAFixVersion is the reason writeJailVEX
// asserts the justification instead of trusting the server.
//
// triage.GenerateOpenVEX contains this, and it is correct for the triage path
// it was written for:
//
//	if f.FixedVer != "" && f.Justification == "" {
//	    stmt["justification"] = "vulnerable_code_not_present"
//	    stmt["status"] = "not_affected"
//	}
//
// A jail statement is the precise inverse: affected, past policy, AND a fix
// exists. Without a justification the emitted document would tell every
// downstream consumer that the repository is NOT affected by the very
// vulnerabilities that failed its build.
func TestJailVEXKeepsAffectedStatusWithAFixVersion(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "jail.vex.json")

	resp := &vdb.CliJailResponse{
		Vex: &vdb.CliJailVexPayload{
			DocumentID: "urn:test:1",
			Author:     "Vulnetix",
			Statements: []vdb.CliJailVexStatement{
				{
					VulnID:           "CVE-2024-0001",
					Package:          "left-pad",
					Ecosystem:        "npm",
					InstalledVersion: "1.0.0",
					FixedVersion:     "1.3.0",
					Status:           "affected",
					// Deliberately empty — the failure mode under test.
					Justification: "",
				},
				{
					VulnID:           "CVE-2024-0002",
					Package:          "moment",
					Ecosystem:        "npm",
					InstalledVersion: "2.29.4",
					FixedVersion:     "2.30.1",
					Status:           "affected",
					Justification:    "remediation_window_exceeded",
				},
			},
		},
	}

	path, err := writeJailVEX(resp, out, "openvex")
	if err != nil {
		t.Fatalf("writeJailVEX: %v", err)
	}
	if path != out {
		t.Fatalf("path = %q, want %q", path, out)
	}

	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var doc struct {
		Statements []struct {
			Vulnerability struct {
				Name string `json:"name"`
			} `json:"vulnerability"`
			Status        string `json:"status"`
			Justification string `json:"justification"`
			FixedVersion  string `json:"fixed_version"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Statements) != 2 {
		t.Fatalf("statements = %d, want 2", len(doc.Statements))
	}

	for _, s := range doc.Statements {
		if s.Status != "affected" {
			t.Fatalf("%s status = %q, want affected — the document asserts the opposite of the verdict that produced it",
				s.Vulnerability.Name, s.Status)
		}
		if s.Justification == "" {
			t.Fatalf("%s has an empty justification", s.Vulnerability.Name)
		}
		if s.FixedVersion == "" {
			t.Fatalf("%s lost its fixed_version", s.Vulnerability.Name)
		}
	}
}

func TestJailVEXCycloneDXFormat(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "jail.cdx.json")

	resp := &vdb.CliJailResponse{
		Vex: &vdb.CliJailVexPayload{
			DocumentID: "urn:test:2",
			Author:     "Vulnetix",
			Statements: []vdb.CliJailVexStatement{{
				VulnID:           "CVE-2024-0003",
				Package:          "requests",
				Ecosystem:        "pypi",
				InstalledVersion: "2.31.0",
				Status:           "affected",
				Justification:    "remediation_window_exceeded",
				Severity:         "high",
			}},
		},
	}

	if _, err := writeJailVEX(resp, out, "cyclonedx"); err != nil {
		t.Fatalf("writeJailVEX: %v", err)
	}

	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc["bomFormat"] != "CycloneDX" {
		t.Fatalf("bomFormat = %v, want CycloneDX", doc["bomFormat"])
	}
	if _, ok := doc["vulnerabilities"]; !ok {
		t.Fatal("CycloneDX document carries no vulnerabilities array")
	}
}

// TestJailVEXEmptyPayloadWritesNothing pins that a clean gate leaves no stale
// artefact behind claiming otherwise.
func TestJailVEXEmptyPayloadWritesNothing(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "jail.vex.json")

	for _, resp := range []*vdb.CliJailResponse{
		nil,
		{},
		{Vex: &vdb.CliJailVexPayload{}},
	} {
		path, err := writeJailVEX(resp, out, "openvex")
		if err != nil {
			t.Fatalf("writeJailVEX: %v", err)
		}
		if path != "" {
			t.Fatalf("path = %q, want empty", path)
		}
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("an empty payload still created a file")
	}
}

func TestJailSARIFRendersNonVulnBreaches(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "jail.sarif")

	resp := &vdb.CliJailResponse{
		Sarif: &vdb.CliJailSarifPayload{
			Rules: []vdb.CliJailSarifRule{{
				ID:          "VULNETIX-JAIL-EOL-no-retired-runtimes",
				Name:        "no retired runtimes",
				Description: "1 retired runtime",
				Severity:    "high",
				Level:       "error",
				Tags:        []string{"vulnetix-jail", "eol"},
			}},
			Results: []vdb.CliJailSarifResult{{
				RuleID:      "VULNETIX-JAIL-EOL-no-retired-runtimes",
				Message:     "pkg:npm/node — 1 retired",
				ArtifactURI: ".",
				Severity:    "high",
				Level:       "error",
			}},
		},
	}

	path, err := writeJailSARIF(resp, out)
	if err != nil {
		t.Fatalf("writeJailSARIF: %v", err)
	}
	if path != out {
		t.Fatalf("path = %q, want %q", path, out)
	}

	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.Version == "" {
		t.Fatal("SARIF document has no version")
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 {
		t.Fatalf("runs/results = %d/%v, want 1 run with 1 result", len(doc.Runs), doc.Runs)
	}
	if doc.Runs[0].Results[0].RuleID != "VULNETIX-JAIL-EOL-no-retired-runtimes" {
		t.Fatalf("ruleId = %q", doc.Runs[0].Results[0].RuleID)
	}
}

// TestJailArtifactCreatesParentDirectory pins that a first run in a fresh
// checkout, where .vulnetix does not exist yet, still writes its evidence.
func TestJailArtifactCreatesParentDirectory(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "nested", "deeper", "jail.vex.json")

	resp := &vdb.CliJailResponse{
		Vex: &vdb.CliJailVexPayload{
			Statements: []vdb.CliJailVexStatement{{
				VulnID:        "CVE-2024-0004",
				Status:        "affected",
				Justification: "remediation_window_exceeded",
			}},
		},
	}
	if _, err := writeJailVEX(resp, out, "openvex"); err != nil {
		t.Fatalf("writeJailVEX: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("artefact not written: %v", err)
	}
}
