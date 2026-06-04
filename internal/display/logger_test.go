package display

import (
	"strings"
	"testing"
)

func TestNewLogger(t *testing.T) {
	term := NewTerminal()
	l := NewLogger(ModeText, false, term)
	if l == nil {
		t.Fatal("expected non-nil Logger")
	}
	if l.silent {
		t.Error("expected non-silent")
	}

	l2 := NewLogger(ModeText, true, term)
	if !l2.silent {
		t.Error("expected silent")
	}
}

func TestStripEmoji(t *testing.T) {
	tests := []struct {
		input   string
		contain string
	}{
		{"plain text", "plain text"},
		{"", ""},
	}
	for _, tc := range tests {
		got := stripEmoji(tc.input)
		if got != tc.contain {
			t.Errorf("stripEmoji(%q): expected %q, got %q", tc.input, tc.contain, got)
		}
	}

	// Emoji should be stripped
	if result := stripEmoji("Hello 🚀 World"); !strings.Contains(result, "Hello") {
		t.Errorf("expected Hello in result, got %q", result)
	}
	if result := stripEmoji("✅ Task done"); strings.Contains(result, "✅") {
		t.Errorf("emoji should be stripped, got %q", result)
	}
	// ✔ is in the emoji strip range
	if result := stripEmoji("✔ check"); strings.Contains(result, "✔") {
		t.Errorf("checkmark emoji should be stripped, got %q", result)
	}
	if result := stripEmoji("⚠ Warning"); strings.Contains(result, "⚠") {
		t.Errorf("warning emoji should be stripped, got %q", result)
	}
}
