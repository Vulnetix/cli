package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulnetix/cli/v4/pkg/vdb"
)

// TestJailVEXKeepsAffectedStatusWithAFixVersion pins the jail document to its
// verdict: affected, past policy, and a fix exists.
//
// triage.GenerateOpenVEX once rewrote an affected statement that had a fix
// version and no justification to not_affected, which would have told every
// downstream consumer the repository is not affected by the vulnerabilities
// that failed its build. The fix version now goes into action_statement and
// the jail's reason into status_notes.
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
			Status          string `json:"status"`
			Justification   string `json:"justification"`
			ActionStatement string `json:"action_statement"`
			StatusNotes     string `json:"status_notes"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Statements) != 2 {
		t.Fatalf("statements = %d, want 2", len(doc.Statements))
	}

	fixedIn := map[string]string{"CVE-2024-0001": "1.3.0", "CVE-2024-0002": "2.30.1"}
	for _, s := range doc.Statements {
		if s.Status != "affected" {
			t.Fatalf("%s status = %q, want affected: the document asserts the opposite of the verdict that produced it",
				s.Vulnerability.Name, s.Status)
		}
		// OpenVEX justifications belong to not_affected only, so the jail's
		// reason travels in status_notes.
		if s.Justification != "" {
			t.Fatalf("%s carries justification %q on an affected statement", s.Vulnerability.Name, s.Justification)
		}
		if !strings.Contains(s.StatusNotes, "justification: ") {
			t.Fatalf("%s lost its reason; status_notes = %q", s.Vulnerability.Name, s.StatusNotes)
		}
		if !strings.Contains(s.ActionStatement, fixedIn[s.Vulnerability.Name]) {
			t.Fatalf("%s action_statement %q does not name the fix %s", s.Vulnerability.Name, s.ActionStatement, fixedIn[s.Vulnerability.Name])
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
