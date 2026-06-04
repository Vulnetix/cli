package display

import (
	"testing"
)

func TestNew(t *testing.T) {
	c := New(ModeJSON, false)
	if c == nil {
		t.Fatal("expected non-nil Context")
	}
	if c.Mode != ModeJSON {
		t.Errorf("expected ModeJSON, got %d", c.Mode)
	}
	if c.Silent {
		t.Error("expected non-silent")
	}
}

func TestNewWithProgress(t *testing.T) {
	c := NewWithProgress(ModeText, true, true)
	if c == nil {
		t.Fatal("expected non-nil Context")
	}
	if !c.Silent {
		t.Error("expected silent")
	}
	if !c.NoProgress {
		t.Error("expected no-progress")
	}
}

func TestNewFromFlags(t *testing.T) {
	c := NewFromFlags("json", false)
	if c.Mode != ModeJSON {
		t.Errorf("expected ModeJSON, got %d", c.Mode)
	}

	c2 := NewFromFlags("text", false)
	if c2.Mode != ModeText {
		t.Errorf("expected ModeText, got %d", c2.Mode)
	}
}

func TestIsJSON(t *testing.T) {
	c := New(ModeJSON, false)
	if !c.IsJSON() {
		t.Error("expected IsJSON true")
	}

	c2 := New(ModeText, false)
	if c2.IsJSON() {
		t.Error("expected IsJSON false for text mode")
	}
}
