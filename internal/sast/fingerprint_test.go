package sast

import (
	"testing"
)

func TestFingerprint_Deterministic(t *testing.T) {
	a := Fingerprint("rule-1", "main.go", 42)
	b := Fingerprint("rule-1", "main.go", 42)
	if a != b {
		t.Fatalf("same inputs should produce same hash: got %q vs %q", a, b)
	}
	if len(a) != 16 {
		t.Fatalf("expected 16 hex chars, got %d: %q", len(a), a)
	}
}

func TestFingerprint_DifferentRuleID(t *testing.T) {
	a := Fingerprint("rule-1", "main.go", 10)
	b := Fingerprint("rule-2", "main.go", 10)
	if a == b {
		t.Fatal("different rule IDs should produce different hashes")
	}
}

func TestFingerprint_DifferentURI(t *testing.T) {
	a := Fingerprint("rule-1", "main.go", 10)
	b := Fingerprint("rule-1", "parser.go", 10)
	if a == b {
		t.Fatal("different URIs should produce different hashes")
	}
}

func TestFingerprint_DifferentLine(t *testing.T) {
	a := Fingerprint("rule-1", "main.go", 10)
	b := Fingerprint("rule-1", "main.go", 11)
	if a == b {
		t.Fatal("different lines should produce different hashes")
	}
}

func TestFingerprint_EmptyInputs(t *testing.T) {
	fp := Fingerprint("", "", 0)
	if len(fp) != 16 {
		t.Fatalf("expected 16 hex chars, got %d: %q", len(fp), fp)
	}
	// Should be deterministic even with empty inputs
	if fp2 := Fingerprint("", "", 0); fp != fp2 {
		t.Fatalf("empty inputs should be deterministic: %q vs %q", fp, fp2)
	}
}
