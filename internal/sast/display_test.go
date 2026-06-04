package sast

import (
	"testing"
)

func TestSeverityBreakdown(t *testing.T) {
	report := &SASTReport{
		Findings: []Finding{
			{Severity: "critical"},
			{Severity: "high"},
			{Severity: "high"},
			{Severity: "medium"},
			{Severity: "low"},
			{Severity: "info"},
		},
	}

	total, parts := severityBreakdown(report)
	if total != 6 {
		t.Errorf("expected 6 total, got %d", total)
	}
	expectedParts := []string{"1 critical", "2 high", "1 medium", "1 low", "1 info"}
	if len(parts) != len(expectedParts) {
		t.Fatalf("expected %d parts, got %d: %v", len(expectedParts), len(parts), parts)
	}
	for i, p := range parts {
		if p != expectedParts[i] {
			t.Errorf("parts[%d]: expected %q, got %q", i, expectedParts[i], p)
		}
	}
}

func TestSeverityBreakdown_Empty(t *testing.T) {
	report := &SASTReport{}
	total, parts := severityBreakdown(report)
	if total != 0 {
		t.Errorf("expected 0 total, got %d", total)
	}
	if len(parts) != 0 {
		t.Errorf("expected 0 parts, got %d", len(parts))
	}
}

func TestRulesEvaluatedPhrase_Exact(t *testing.T) {
	r := &SASTReport{RulesLoaded: 10, RulesTotal: 10}
	got := rulesEvaluatedPhrase(r)
	if got != "10 rules" {
		t.Errorf("expected '10 rules', got %q", got)
	}
}

func TestRulesEvaluatedPhrase_Filtered(t *testing.T) {
	r := &SASTReport{RulesLoaded: 5, RulesTotal: 10}
	got := rulesEvaluatedPhrase(r)
	if got != "5 of 10 rules" {
		t.Errorf("expected '5 of 10 rules', got %q", got)
	}
}

func TestPluralize(t *testing.T) {
	tests := []struct {
		word string
		n    int
		want string
	}{
		{"finding", 0, "findings"},
		{"finding", 1, "finding"},
		{"finding", 2, "findings"},
		{"rule", 1, "rule"},
		{"rule", 5, "rules"},
	}
	for _, tc := range tests {
		got := pluralize(tc.word, tc.n)
		if got != tc.want {
			t.Errorf("pluralize(%q, %d): expected %q, got %q", tc.word, tc.n, tc.want, got)
		}
	}
}

func TestSeverityOrd(t *testing.T) {
	tests := []struct {
		sev  string
		want int
	}{
		{"critical", 0},
		{"high", 1},
		{"medium", 2},
		{"low", 3},
		{"info", 4},
		{"unknown", 5},
		{"", 5},
	}
	for _, tc := range tests {
		got := severityOrd(tc.sev)
		if got != tc.want {
			t.Errorf("severityOrd(%q): expected %d, got %d", tc.sev, tc.want, got)
		}
	}
}
