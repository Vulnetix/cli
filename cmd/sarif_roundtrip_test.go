package cmd

import (
	"testing"

	"github.com/Vulnetix/vdb-sca-match/sarif"
	"github.com/vulnetix/cli/v3/internal/sast"
)

// The server now re-decomposes every submitted SARIF document with the shared
// parser and treats its own result as authoritative for the SARIF-derived
// fields. That is only safe if a document this CLI wrote decomposes back to what
// it meant — otherwise a first-party scan would quietly lose severity, CWEs or
// fingerprints on the way through.
//
// This test locks the round trip: sast.BuildSARIF -> sarif.Decompose.
func TestFirstPartySARIFSurvivesRoundTrip(t *testing.T) {
	rules := []sast.RuleMetadata{{
		ID:          "VULNETIX-SQL-001",
		Name:        "sql-injection",
		Description: "String-concatenated SQL query",
		Severity:    "critical",
		Level:       "error",
		Kind:        "sast",
		CWE:         []int{89, 20},
		Tags:        []string{"injection", "owasp-a03"},
		HelpURI:     "https://vulnetix.com/rules/sql-001",
	}}
	findings := []sast.Finding{{
		RuleID:      "VULNETIX-SQL-001",
		Message:     "Query built by concatenation",
		ArtifactURI: "internal/db/query.go",
		Severity:    "critical",
		Level:       "error",
		StartLine:   17,
		EndLine:     19,
		Snippet:     "db.Query(\"SELECT * FROM t WHERE id = \" + id)",
		Fingerprint: "abc123fingerprint",
		Metadata:    &rules[0],
	}}

	doc := sast.BuildSARIF(findings, rules, "v3.65.0")
	raw, err := sarif.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	parsed, report := sarif.ValidateBytes(raw, 50000)
	if report.HasErrors() {
		t.Fatalf("our own SARIF failed validation:\n%s", report)
	}

	got, sum := sarif.Decompose(parsed, sarif.DecomposeOptions{})
	if len(got) != 1 {
		t.Fatalf("decomposed %d findings, want 1", len(got))
	}
	f := got[0]

	if f.RuleID != "VULNETIX-SQL-001" {
		t.Errorf("ruleId = %q", f.RuleID)
	}
	if f.Severity != "critical" {
		t.Errorf("severity = %q, want critical (carried in result.properties.severity)", f.Severity)
	}
	if f.Level != "error" {
		t.Errorf("level = %q", f.Level)
	}
	if f.File != "internal/db/query.go" || f.StartLine != 17 || f.EndLine != 19 {
		t.Errorf("location = %s:%d-%d", f.File, f.StartLine, f.EndLine)
	}
	if f.Fingerprint != "abc123fingerprint" {
		t.Errorf("fingerprint = %q; the vulnetix/v1 key must round-trip", f.Fingerprint)
	}
	// SarifResults is keyed on this; an empty value would break idempotency.
	if f.SARIFGuid == "" {
		t.Error("SARIFGuid must never be empty")
	}
	if len(f.CWEs) != 2 || f.CWEs[0] != 20 || f.CWEs[1] != 89 {
		t.Errorf("cwes = %v, want [20 89] (sorted)", f.CWEs)
	}
	if f.RuleName != "sql-injection" {
		t.Errorf("ruleName = %q", f.RuleName)
	}
	if f.Description == "" {
		t.Error("description should come from the rule's shortDescription")
	}
	if f.HelpURI != "https://vulnetix.com/rules/sql-001" {
		t.Errorf("helpUri = %q", f.HelpURI)
	}
	if sum.Tool.Name != "vulnetix" {
		t.Errorf("tool = %q, want vulnetix", sum.Tool.Name)
	}
	if sum.Rules != 1 {
		t.Errorf("rules = %d, want 1", sum.Rules)
	}
}

// An enabled-but-clean scanner submits an empty document so the backend records
// coverage rather than nothing. That must not be mistaken for a broken file.
func TestEmptyFirstPartySARIFIsValid(t *testing.T) {
	doc := sast.BuildSARIF(nil, nil, "v3.65.0")
	raw, err := sarif.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	parsed, report := sarif.ValidateBytes(raw, 50000)
	if report.HasErrors() {
		t.Fatalf("an empty scan report must validate:\n%s", report)
	}
	findings, sum := sarif.Decompose(parsed, sarif.DecomposeOptions{})
	if len(findings) != 0 {
		t.Errorf("findings = %d, want 0", len(findings))
	}
	if sum.Tool.Name != "vulnetix" {
		t.Errorf("tool = %q; coverage is only recorded if the run is attributable", sum.Tool.Name)
	}
}
