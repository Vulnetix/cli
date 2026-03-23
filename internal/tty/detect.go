package tty

import (
	"os"

	"golang.org/x/term"
)

// IsInteractive returns true if stderr is a terminal.
// We check stderr (not stdout) because stdout may be piped for data output
// while stderr remains the user's terminal for progress/TUI.
func IsInteractive() bool {
	return term.IsTerminal(int(os.Stderr.Fd()))
}

// StderrIsTerminal returns true if stderr is connected to a terminal.
func StderrIsTerminal() bool {
	return term.IsTerminal(int(os.Stderr.Fd()))
}

// StdoutIsTerminal returns true if stdout is connected to a terminal.
func StdoutIsTerminal() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}
