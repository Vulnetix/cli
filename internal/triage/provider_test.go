package triage

import (
	"testing"
)

func TestAlert_Identifier_CVE(t *testing.T) {
	a := Alert{
		CVE:       "CVE-2024-0001",
		Package:   "lodash",
		Ecosystem: "npm",
	}
	if id := a.Identifier(); id != "CVE-2024-0001" {
		t.Errorf("expected 'CVE-2024-0001', got %q", id)
	}
}

func TestAlert_Identifier_RuleID(t *testing.T) {
	a := Alert{
		RuleID:    "js/bad-tag-filter",
		Package:   "test",
		Ecosystem: "npm",
	}
	if id := a.Identifier(); id != "js/bad-tag-filter" {
		t.Errorf("expected 'js/bad-tag-filter', got %q", id)
	}
}

func TestAlert_Identifier_Number(t *testing.T) {
	a := Alert{
		Number:  "42",
		Package: "test",
	}
	if id := a.Identifier(); id != "#42" {
		t.Errorf("expected '#42', got %q", id)
	}
}

func TestFixesMerged_HasFix(t *testing.T) {
	f := &FixesMerged{}
	if f.HasFix() {
		t.Error("expected false for empty FixesMerged")
	}
}

func TestGitHubToolKinds(t *testing.T) {
	if len(GitHubToolKinds) != 3 {
		t.Errorf("expected 3 tool kinds, got %d", len(GitHubToolKinds))
	}
}

func TestTriageFinding_Fields(t *testing.T) {
	f := TriageFinding{
		CVEID:  "CVE-2024-0001",
		Status: "affected",
	}
	if f.CVEID != "CVE-2024-0001" || f.Status != "affected" {
		t.Errorf("unexpected values: %+v", f)
	}
}

func TestEnrichedAlert_Fields(t *testing.T) {
	a := EnrichedAlert{
		Error: "test error",
	}
	if a.Error != "test error" {
		t.Errorf("expected 'test error', got %q", a.Error)
	}
}

func TestThreatModel_Fields(t *testing.T) {
	tm := ThreatModel{
		Techniques: []string{"T1190"},
	}
	if len(tm.Techniques) != 1 || tm.Techniques[0] != "T1190" {
		t.Errorf("unexpected techniques: %v", tm.Techniques)
	}
}
