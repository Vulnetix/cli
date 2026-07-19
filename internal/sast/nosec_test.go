package sast

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestApplyNosec(t *testing.T) {
	dir := t.TempDir()
	// line 2 bare nosec; line 4 rule-specific; line 1 whole-file in b.py
	writeFile(t, dir, "a.go", "package a\nx := 1 // nosec\ny := 2\nz := 3 // nosec vnx-320\n")
	writeFile(t, dir, "b.py", "# nosec\nsecret = 1\n")

	findings := []Finding{
		{RuleID: "vnx-100", ArtifactURI: "a.go", StartLine: 2, EndLine: 2}, // dropped (bare)
		{RuleID: "vnx-200", ArtifactURI: "a.go", StartLine: 3, EndLine: 3}, // kept
		{RuleID: "vnx-320", ArtifactURI: "a.go", StartLine: 4, EndLine: 4}, // dropped (rule-specific)
		{RuleID: "vnx-999", ArtifactURI: "a.go", StartLine: 4, EndLine: 4}, // kept (not listed)
		{RuleID: "vnx-777", ArtifactURI: "b.py", StartLine: 2, EndLine: 2}, // dropped (whole-file)
	}

	kept, dropped := ApplyNosec(findings, dir)
	if dropped != 3 {
		t.Fatalf("dropped = %d, want 3", dropped)
	}
	keptRules := map[string]bool{}
	for _, f := range kept {
		keptRules[f.RuleID] = true
	}
	if !keptRules["vnx-200"] || !keptRules["vnx-999"] {
		t.Errorf("expected vnx-200 and vnx-999 kept, got %v", keptRules)
	}
	if keptRules["vnx-100"] || keptRules["vnx-320"] || keptRules["vnx-777"] {
		t.Errorf("unexpected kept finding: %v", keptRules)
	}
}
