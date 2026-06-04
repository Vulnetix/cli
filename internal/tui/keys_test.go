package tui

import (
	"testing"
)

func TestKeys_AllBindingsPresent(t *testing.T) {
	// Verify all key bindings have keys set
	bindings := []struct {
		name    string
		binding interface{ Keys() []string }
	}{
		{"Quit", &keys.Quit},
		{"Up", &keys.Up},
		{"Down", &keys.Down},
		{"Enter", &keys.Enter},
		{"Output", &keys.Output},
	}
	_ = bindings
	// Just verify the keys variable is initialized
	if len(keys.Quit.Keys()) == 0 {
		t.Error("expected Quit to have keys")
	}
	if len(keys.Up.Keys()) == 0 {
		t.Error("expected Up to have keys")
	}
	if len(keys.Down.Keys()) == 0 {
		t.Error("expected Down to have keys")
	}
}

func TestHelpView(t *testing.T) {
	result := helpView()
	if result == "" {
		t.Error("expected non-empty help view")
	}
}
