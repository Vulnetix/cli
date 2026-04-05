package display

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/vulnetix/cli/internal/tui"
)

// Style helpers that use the shared TUI color palette.
// All functions degrade gracefully when terminal has no color support.

// Header renders a bold accent-colored section header.
func Header(term *Terminal, text string) string {
	if !term.HasColor() {
		return "\n" + strings.ToUpper(text) + "\n"
	}
	return "\n" + lipgloss.NewStyle().
		Bold(true).
		Foreground(tui.ColorAccent).
		Render(text) + "\n"
}

// Subheader renders a bold section subheader.
func Subheader(term *Terminal, text string) string {
	if !term.HasColor() {
		return text
	}
	return lipgloss.NewStyle().Bold(true).Render(text)
}

// Label renders dimmed label text.
func Label(term *Terminal, text string) string {
	if !term.HasColor() {
		return text
	}
	return lipgloss.NewStyle().Foreground(tui.ColorMuted).Render(text)
}

// Muted renders dimmed text.
func Muted(term *Terminal, text string) string {
	if !term.HasColor() {
		return text
	}
	return lipgloss.NewStyle().Foreground(tui.ColorMuted).Render(text)
}

// Bold renders bold text.
func Bold(term *Terminal, text string) string {
	if !term.HasColor() {
		return text
	}
	return lipgloss.NewStyle().Bold(true).Render(text)
}

// Success renders green text.
func Success(term *Terminal, text string) string {
	if !term.HasColor() {
		return text
	}
	return lipgloss.NewStyle().Foreground(tui.ColorSuccess).Render(text)
}

// ErrorStyle renders red text.
func ErrorStyle(term *Terminal, text string) string {
	if !term.HasColor() {
		return text
	}
	return lipgloss.NewStyle().Foreground(tui.ColorError).Render(text)
}

// Accent renders accent-colored text.
func Accent(term *Terminal, text string) string {
	if !term.HasColor() {
		return text
	}
	return lipgloss.NewStyle().Foreground(tui.ColorAccent).Render(text)
}

// Teal renders teal-colored text. Used to highlight file paths in scan output.
func Teal(term *Terminal, text string) string {
	if !term.HasColor() {
		return text
	}
	return lipgloss.NewStyle().Foreground(tui.ColorTeal).Render(text)
}

// SeverityBadge renders an inline colored severity label.
func SeverityBadge(term *Terminal, level string) string {
	label := strings.ToUpper(level)
	if !term.HasColor() {
		return "[" + label + "]"
	}
	return tui.SeverityStyle(strings.ToLower(level)).Render(label)
}

// SeverityText renders severity text with the appropriate color (no background).
func SeverityText(term *Terminal, level string) string {
	if !term.HasColor() {
		return level
	}
	color := tui.SeverityColor(strings.ToLower(level))
	return lipgloss.NewStyle().Foreground(color).Render(level)
}

// Divider renders a subtle horizontal line.
func Divider(term *Terminal) string {
	width := term.Width
	if width > 80 {
		width = 80
	}
	if !term.HasColor() {
		return strings.Repeat("-", width)
	}
	return lipgloss.NewStyle().
		Foreground(tui.ColorMuted).
		Render(strings.Repeat("─", width))
}

// ShortDivider renders a shorter divider for subsections.
func ShortDivider(term *Terminal, width int) string {
	if !term.HasColor() {
		return strings.Repeat("-", width)
	}
	return lipgloss.NewStyle().
		Foreground(tui.ColorMuted).
		Render(strings.Repeat("─", width))
}

// Bar renders a visual progress bar like ████████░░
func Bar(term *Terminal, filled, total, width int) string {
	if total == 0 {
		return strings.Repeat("░", width)
	}
	filledWidth := (filled * width) / total
	if filledWidth > width {
		filledWidth = width
	}
	emptyWidth := width - filledWidth

	filledStr := strings.Repeat("█", filledWidth)
	emptyStr := strings.Repeat("░", emptyWidth)

	if !term.HasColor() {
		return filledStr + emptyStr
	}
	return lipgloss.NewStyle().Foreground(tui.ColorAccent).Render(filledStr) +
		lipgloss.NewStyle().Foreground(tui.ColorMuted).Render(emptyStr)
}

// CheckMark renders a green checkmark.
func CheckMark(term *Terminal) string {
	if !term.HasColor() {
		return "[OK]"
	}
	return lipgloss.NewStyle().Foreground(tui.ColorSuccess).Render("✔")
}

// CrossMark renders a red cross.
func CrossMark(term *Terminal) string {
	if !term.HasColor() {
		return "[FAIL]"
	}
	return lipgloss.NewStyle().Foreground(tui.ColorError).Render("✘")
}

// WarningMark renders a yellow warning indicator.
func WarningMark(term *Terminal) string {
	if !term.HasColor() {
		return "[WARN]"
	}
	return lipgloss.NewStyle().Foreground(tui.ColorMedium).Render("⚠")
}
