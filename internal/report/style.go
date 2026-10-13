package report

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/scaview"
	"github.com/vulnetix/cli/v3/internal/tui"
)

// glyphs are the symbols the renderers draw with. Each has a plain-ASCII twin so
// the output survives TERM=dumb, --ascii and a log viewer that mangles unicode.
type glyphs struct {
	Dot, Signal, OK, Fail, Unknown, Arrow, Defence, Sep, Rule, Ellipsis, Bar string
}

var (
	unicodeGlyphs = glyphs{"●", "▲", "✔", "✖", "?", "→", "◆", "·", "─", "…", "│"}
	asciiGlyphs   = glyphs{"*", "^", "+", "x", "?", "->", "#", "|", "-", "...", "|"}
)

// purple marks defences. It is deliberately not one of the severity colours: a
// defence is a different kind of thing from a finding.
var purple = lipgloss.Color("#AF87FF")

// Style draws text for one terminal. With colour off every method returns its
// input unchanged, so tests and pipes see exactly the characters, no escapes.
type Style struct {
	T     *display.Terminal
	G     glyphs
	Width int
	// fixW is the widest "what do I do" cell in the report being drawn, so the
	// column after it lines up whatever the fixes turn out to say.
	fixW  int
	color bool
}

// NewStyle builds a Style from a terminal and the display options.
func NewStyle(t *display.Terminal, o Options) *Style {
	s := &Style{T: t, G: unicodeGlyphs, Width: 80}
	if t != nil {
		s.Width = t.Width
		s.color = t.HasColor()
	}
	if o.Width > 0 {
		s.Width = o.Width
	}
	if s.Width < 30 {
		s.Width = 30
	}
	if o.ASCII {
		s.G = asciiGlyphs
	}
	return s
}

func (s *Style) paint(c lipgloss.TerminalColor, bold bool, text string) string {
	if !s.color || text == "" {
		return text
	}
	st := lipgloss.NewStyle().Foreground(c)
	if bold {
		st = st.Bold(true)
	}
	return st.Render(text)
}

// Dim is secondary text.
func (s *Style) Dim(t string) string { return s.paint(tui.ColorMuted, false, t) }

// Bold is emphasis without a colour.
func (s *Style) Bold(t string) string {
	if !s.color || t == "" {
		return t
	}
	return lipgloss.NewStyle().Bold(true).Render(t)
}

// Good is success and fixes.
func (s *Style) Good(t string) string { return s.paint(tui.ColorSuccess, false, t) }

// Bad is failure.
func (s *Style) Bad(t string) string { return s.paint(tui.ColorError, true, t) }

// Warn is caution.
func (s *Style) Warn(t string) string { return s.paint(tui.ColorMedium, false, t) }

// Hot is the orange used for "no fix" and strong signals.
func (s *Style) Hot(t string) string { return s.paint(tui.ColorHigh, true, t) }

// Cmd is a command the reader can run.
func (s *Style) Cmd(t string) string { return s.paint(tui.ColorAccent, false, t) }

// Path is a file path.
func (s *Style) Path(t string) string { return s.paint(tui.ColorTeal, false, t) }

// Defence is the colour for protection lines.
func (s *Style) Defence(t string) string { return s.paint(purple, false, t) }

// Sev colours a word by severity.
func (s *Style) Sev(level, text string) string {
	return s.paint(tui.SeverityColor(strings.ToLower(level)), true, text)
}

// SevWord is the fixed-width uppercase severity word.
func SevWord(level string) string {
	switch scaview.NormaliseSeverity(level) {
	case "critical":
		return "CRITICAL"
	case "high":
		return "HIGH"
	case "medium":
		return "MEDIUM"
	case "low":
		return "LOW"
	}
	return "INFO"
}

// Rule draws a horizontal rule.
func (s *Style) Rule(width int) string {
	if width > s.Width-2 {
		width = s.Width - 2
	}
	if width > 96 {
		width = 96
	}
	if width < 8 {
		width = 8
	}
	return s.Dim(strings.Repeat(s.G.Rule, width))
}

// vis is the number of cells a string occupies once styled, which is what
// padding has to be measured against. display.Width does not strip escapes.
func vis(s string) int { return lipgloss.Width(s) }

// pad right-pads a styled string to width cells.
func pad(s string, width int) string {
	if n := vis(s); n < width {
		return s + strings.Repeat(" ", width-n)
	}
	return s
}

// clip shortens plain text to width cells with an ellipsis.
func (s *Style) clip(text string, width int) string {
	if width <= 0 {
		return ""
	}
	if display.Width(text) <= width {
		return text
	}
	if s.G.Ellipsis == "..." {
		return display.Truncate(text, width)
	}
	r := []rune(text)
	for len(r) > 0 && display.Width(string(r))+1 > width {
		r = r[:len(r)-1]
	}
	return string(r) + s.G.Ellipsis
}

// plural renders "1 package" or "2 packages".
func plural(n int, singular string) string {
	if n == 1 {
		return "1 " + singular
	}
	return itoaPlural(n) + " " + singular + "s"
}

func itoaPlural(n int) string { return display.FormatNumber(n) }
