package tui

import "github.com/charmbracelet/lipgloss"

// Exported color constants for use by other packages (e.g., internal/display).
var (
	ColorCritical = lipgloss.Color("#FF0000")
	ColorHigh     = lipgloss.Color("#FF8800")
	ColorMedium   = lipgloss.Color("#FFCC00")
	ColorLow      = lipgloss.Color("#0088FF")
	ColorInfo     = lipgloss.Color("#888888")
	ColorSuccess  = lipgloss.Color("#00CC00")
	ColorError    = lipgloss.Color("#FF4444")
	ColorMalware  = lipgloss.Color("#FF00FF")
	ColorMuted    = lipgloss.Color("#666666")
	ColorAccent   = lipgloss.Color("#00CCFF")
	ColorTeal     = lipgloss.Color("#00B4B4")
	ColorWhite    = lipgloss.Color("#FFFFFF")
)

var (
	// Aliases for internal use
	colorCritical = ColorCritical
	colorHigh     = ColorHigh
	colorMedium   = ColorMedium
	colorLow      = ColorLow
	colorInfo     = ColorInfo
	colorSuccess  = ColorSuccess
	colorError    = ColorError
	colorMalware  = ColorMalware
	colorMuted    = ColorMuted
	colorAccent   = ColorAccent
	colorWhite    = ColorWhite

	// Status indicators
	styleCheck   = lipgloss.NewStyle().Foreground(colorSuccess).SetString("\u2714")
	styleCross   = lipgloss.NewStyle().Foreground(colorError).SetString("\u2718")
	styleMalware = lipgloss.NewStyle().Foreground(colorMalware).Bold(true)

	// Severity badge styles
	styleCritical = lipgloss.NewStyle().Foreground(colorWhite).Background(colorCritical).Bold(true).Padding(0, 1)
	styleHigh     = lipgloss.NewStyle().Foreground(colorWhite).Background(colorHigh).Bold(true).Padding(0, 1)
	styleMedium   = lipgloss.NewStyle().Foreground(lipgloss.Color("#000000")).Background(colorMedium).Bold(true).Padding(0, 1)
	styleLow      = lipgloss.NewStyle().Foreground(colorWhite).Background(colorLow).Padding(0, 1)
	styleUnknown  = lipgloss.NewStyle().Foreground(colorWhite).Background(colorInfo).Padding(0, 1)

	// Layout
	styleSummaryBar = lipgloss.NewStyle().
			Bold(true).
			Padding(0, 1).
			MarginBottom(1)

	styleStatusBar = lipgloss.NewStyle().
			Foreground(colorMuted).
			Padding(0, 1)

	styleTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorAccent)

	styleDetailHeader = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorAccent).
				MarginBottom(1)

	styleTabActive = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorAccent).
			Underline(true)

	styleTabInactive = lipgloss.NewStyle().
				Foreground(colorMuted)

	styleDetailContent = lipgloss.NewStyle().
				Padding(0, 1)

	styleOutputMenu = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorAccent).
			Padding(1, 2)

	styleHelp = lipgloss.NewStyle().
			Foreground(colorMuted).
			Padding(0, 1)

	// Task progress styles
	styleFileName = lipgloss.NewStyle().
			Width(40)

	styleElapsed = lipgloss.NewStyle().
			Foreground(colorMuted)

	styleScanID = lipgloss.NewStyle().
			Foreground(colorMuted)
)

// SeverityStyle returns the lipgloss style for a severity level.
func SeverityStyle(severity string) lipgloss.Style {
	switch severity {
	case "critical":
		return styleCritical
	case "high":
		return styleHigh
	case "medium":
		return styleMedium
	case "low":
		return styleLow
	default:
		return styleUnknown
	}
}

// SeverityColor returns the color for a severity level.
func SeverityColor(severity string) lipgloss.Color {
	switch severity {
	case "critical":
		return colorCritical
	case "high":
		return colorHigh
	case "medium":
		return colorMedium
	case "low":
		return colorLow
	default:
		return colorInfo
	}
}
