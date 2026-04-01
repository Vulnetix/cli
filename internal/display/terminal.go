package display

import (
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"golang.org/x/term"
)

// Terminal holds detected terminal capabilities.
type Terminal struct {
	Width        int
	Height       int
	IsTTY        bool // stdout is a terminal
	StderrTTY    bool
	ColorProfile termenv.Profile
}

// NewTerminal detects terminal capabilities.
func NewTerminal() *Terminal {
	t := &Terminal{
		Width:  80,
		Height: 24,
	}
	t.IsTTY = term.IsTerminal(int(os.Stdout.Fd()))
	t.StderrTTY = term.IsTerminal(int(os.Stderr.Fd()))

	if t.StderrTTY {
		if w, h, err := term.GetSize(int(os.Stderr.Fd())); err == nil {
			t.Width = w
			t.Height = h
		}
	} else if t.IsTTY {
		if w, h, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
			t.Width = w
			t.Height = h
		}
	}

	if t.IsTTY || t.StderrTTY {
		t.ColorProfile = termenv.ColorProfile()
	} else {
		t.ColorProfile = termenv.Ascii
	}

	return t
}

// Refresh re-reads terminal dimensions.
func (t *Terminal) Refresh() {
	if t.StderrTTY {
		if w, h, err := term.GetSize(int(os.Stderr.Fd())); err == nil {
			t.Width = w
			t.Height = h
		}
	} else if t.IsTTY {
		if w, h, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
			t.Width = w
			t.Height = h
		}
	}
}

// HasColor returns true if the terminal supports color output.
func (t *Terminal) HasColor() bool {
	return t.ColorProfile != termenv.Ascii
}

// LipglossRenderer returns a lipgloss renderer configured for this terminal.
func (t *Terminal) LipglossRenderer() *lipgloss.Renderer {
	if !t.HasColor() {
		return lipgloss.NewRenderer(os.Stdout, termenv.WithProfile(termenv.Ascii))
	}
	return lipgloss.DefaultRenderer()
}
