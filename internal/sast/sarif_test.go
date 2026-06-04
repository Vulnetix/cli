package sast

import (
	"encoding/json"
	"testing"
)

func TestBuildSARIF_EmptyReport(t *testing.T) {
	log := BuildSARIF(nil, nil, "1.0.0")
	if log == nil {
		t.Fatal("expected non-nil SARIF log")
	}
	if log.Schema != "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json" {
		t.Errorf("unexpected schema: %q", log.Schema)
	}
	if log.Version != "2.1.0" {
		t.Errorf("unexpected version: %q", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}
	if log.Runs[0].Tool.Driver.Name != "vulnetix" {
		t.Errorf("expected tool name 'vulnetix', got %q", log.Runs[0].Tool.Driver.Name)
	}
	if log.Runs[0].Tool.Driver.Version != "1.0.0" {
		t.Errorf("expected tool version '1.0.0', got %q", log.Runs[0].Tool.Driver.Version)
	}
	if len(log.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(log.Runs[0].Results))
	}
	if len(log.Runs[0].Tool.Driver.Rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(log.Runs[0].Tool.Driver.Rules))
	}
}

func TestBuildSARIF_SingleFinding(t *testing.T) {
	findings := []Finding{{
		RuleID:      "rule-1",
		Message:     "test finding",
		ArtifactURI: "main.go",
		Severity:    "high",
		Level:       "error",
		StartLine:   42,
		EndLine:     45,
		Snippet:     "bad code",
		Fingerprint: "abc123",
		Metadata: &RuleMetadata{
			Kind: "pass",
		},
	}}

	log := BuildSARIF(findings, nil, "1.0.0")
	if len(log.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(log.Runs[0].Results))
	}

	r := log.Runs[0].Results[0]
	if r.RuleID != "rule-1" {
		t.Errorf("expected rule-1, got %q", r.RuleID)
	}
	if r.Level != "error" {
		t.Errorf("expected level 'error', got %q", r.Level)
	}
	if r.Kind != "pass" {
		t.Errorf("expected kind 'pass', got %q", r.Kind)
	}
	if r.Message.Text != "test finding" {
		t.Errorf("expected message 'test finding', got %q", r.Message.Text)
	}
	if len(r.Locations) != 1 {
		t.Fatalf("expected 1 location, got %d", len(r.Locations))
	}
	loc := r.Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != "main.go" {
		t.Errorf("expected URI 'main.go', got %q", loc.ArtifactLocation.URI)
	}
	if loc.Region.StartLine != 42 {
		t.Errorf("expected start line 42, got %d", loc.Region.StartLine)
	}
	if loc.Region.EndLine != 45 {
		t.Errorf("expected end line 45, got %d", loc.Region.EndLine)
	}
	if loc.Region.Snippet == nil || loc.Region.Snippet.Text != "bad code" {
		t.Errorf("expected snippet 'bad code', got %v", loc.Region.Snippet)
	}
	if fp, ok := r.Fingerprints["vulnetix/v1"]; !ok || fp != "abc123" {
		t.Errorf("expected fingerprint 'abc123', got %v", r.Fingerprints)
	}
}

func TestBuildSARIF_NoSnippetOrLines(t *testing.T) {
	findings := []Finding{{
		RuleID:      "rule-1",
		ArtifactURI: "main.go",
	}}

	log := BuildSARIF(findings, nil, "1.0.0")
	loc := log.Runs[0].Results[0].Locations[0].PhysicalLocation
	if loc.Region != nil {
		t.Error("expected nil region when no line or snippet")
	}
}

func TestBuildSARIF_WithRules(t *testing.T) {
	rules := []RuleMetadata{{
		ID:          "rule-1",
		Name:        "Test Rule",
		Description: "A test rule",
		HelpURI:     "https://example.com",
		Severity:    "high",
		Tags:        []string{"security", "injection"},
		CWE:         []int{79, 89},
		CAPEC:       []string{"CAPEC-1"},
		ATTACKTech:  []string{"T1190"},
		CVSSv4:      "CVSS:4.0/AV:N/AC:L",
		CWSS:        "CWSS:1.0",
	}}

	log := BuildSARIF(nil, rules, "1.0.0")
	rule := log.Runs[0].Tool.Driver.Rules[0]

	if rule.ID != "rule-1" {
		t.Errorf("expected ID 'rule-1', got %q", rule.ID)
	}
	if rule.Name != "Test Rule" {
		t.Errorf("expected name 'Test Rule', got %q", rule.Name)
	}
	if rule.ShortDescription == nil || rule.ShortDescription.Text != "A test rule" {
		t.Errorf("expected description 'A test rule', got %v", rule.ShortDescription)
	}
	if rule.HelpURI != "https://example.com" {
		t.Errorf("expected help URI 'https://example.com', got %q", rule.HelpURI)
	}

	props := rule.Properties
	if props["severity"] != "high" {
		t.Errorf("expected severity 'high' in properties, got %v", props["severity"])
	}
	if cweList, ok := props["cwe"].([]string); !ok || len(cweList) != 2 || cweList[0] != "CWE-79" {
		t.Errorf("expected CWE list, got %v", props["cwe"])
	}
}

func TestBuildSARIF_RoundtripValidJSON(t *testing.T) {
	findings := []Finding{{
		RuleID:      "rule-1",
		Message:     "test",
		ArtifactURI: "main.go",
		Severity:    "high",
		StartLine:   10,
	}}

	log := BuildSARIF(findings, nil, "1.0.0")
	data, err := json.Marshal(log)
	if err != nil {
		t.Fatalf("failed to marshal SARIF: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal SARIF: %v", err)
	}
	if result["$schema"] == nil {
		t.Error("expected $schema field")
	}
	if result["version"] != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %v", result["version"])
	}
}
