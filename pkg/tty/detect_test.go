package tty

import (
	"testing"
)

func TestIsInteractive_ReturnsBool(t *testing.T) {
	// Can't assert true/false since it depends on the test runner,
	// but we can verify it doesn't panic and returns a bool.
	result := IsInteractive()
	_ = result // just verify it compiles and runs
}

func TestStderrIsTerminal_ReturnsBool(t *testing.T) {
	result := StderrIsTerminal()
	_ = result
}

func TestStdoutIsTerminal_ReturnsBool(t *testing.T) {
	result := StdoutIsTerminal()
	_ = result
}
