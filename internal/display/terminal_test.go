package display

import (
	"testing"
)

func TestNewTerminal(t *testing.T) {
	term := NewTerminal()
	if term == nil {
		t.Fatal("expected non-nil Terminal")
	}
	if term.Width == 0 {
		t.Error("expected non-zero width")
	}
	if term.Height == 0 {
		t.Error("expected non-zero height")
	}
	// Width/height default to 80/24 when not a TTY
}

func TestTerminal_HasColor(t *testing.T) {
	term := NewTerminal()
	_ = term.HasColor() // may be true or false
}

func TestTerminal_LipglossRenderer(t *testing.T) {
	term := NewTerminal()
	r := term.LipglossRenderer()
	if r == nil {
		t.Fatal("expected non-nil renderer")
	}
}

func TestTerminal_Refresh(t *testing.T) {
	term := NewTerminal()
	w := term.Width
	h := term.Height
	term.Refresh()
	// Width and height may or may not change; just verify no panic
	_ = w
	_ = h
}
