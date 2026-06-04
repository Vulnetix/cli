package sast

import (
	"testing"
)

func TestEffectiveLevel_ExplicitLevel(t *testing.T) {
	m := &RuleMetadata{Level: "error", Severity: "low"}
	if l := m.EffectiveLevel(); l != "error" {
		t.Fatalf("expected 'error', got %q", l)
	}
}

func TestEffectiveLevel_DerivedCritical(t *testing.T) {
	m := &RuleMetadata{Severity: "critical"}
	if l := m.EffectiveLevel(); l != "error" {
		t.Fatalf("expected 'error' for critical, got %q", l)
	}
}

func TestEffectiveLevel_DerivedHigh(t *testing.T) {
	m := &RuleMetadata{Severity: "high"}
	if l := m.EffectiveLevel(); l != "error" {
		t.Fatalf("expected 'error' for high, got %q", l)
	}
}

func TestEffectiveLevel_DerivedMedium(t *testing.T) {
	m := &RuleMetadata{Severity: "medium"}
	if l := m.EffectiveLevel(); l != "warning" {
		t.Fatalf("expected 'warning' for medium, got %q", l)
	}
}

func TestEffectiveLevel_DerivedLow(t *testing.T) {
	m := &RuleMetadata{Severity: "low"}
	if l := m.EffectiveLevel(); l != "note" {
		t.Fatalf("expected 'note' for low, got %q", l)
	}
}

func TestEffectiveLevel_DerivedInfo(t *testing.T) {
	m := &RuleMetadata{Severity: "info"}
	if l := m.EffectiveLevel(); l != "note" {
		t.Fatalf("expected 'note' for info, got %q", l)
	}
}

func TestEffectiveLevel_UnknownSeverity(t *testing.T) {
	m := &RuleMetadata{Severity: "unknown"}
	if l := m.EffectiveLevel(); l != "warning" {
		t.Fatalf("expected fallback 'warning' for unknown severity, got %q", l)
	}
}

func TestEffectiveLevel_Empty(t *testing.T) {
	m := &RuleMetadata{}
	if l := m.EffectiveLevel(); l != "warning" {
		t.Fatalf("expected fallback 'warning' for empty, got %q", l)
	}
}

func TestSeverityToLevel_AllKeys(t *testing.T) {
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if _, ok := SeverityToLevel[sev]; !ok {
			t.Fatalf("SeverityToLevel missing key %q", sev)
		}
	}
}

func TestSeverityLabel_AllKeys(t *testing.T) {
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if _, ok := SeverityLabel[sev]; !ok {
			t.Fatalf("SeverityLabel missing key %q", sev)
		}
	}
	if SeverityLabel["critical"] != "Dangerous" {
		t.Fatal("expected 'Dangerous' for critical")
	}
	if SeverityLabel["high"] != "Risky" {
		t.Fatal("expected 'Risky' for high")
	}
}
