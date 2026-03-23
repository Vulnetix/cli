package tui

import "github.com/charmbracelet/lipgloss"

var (
	// Colors
	colorCritical = lipgloss.Color("#FF0000")
	colorHigh     = lipgloss.Color("#FF8800")
	colorMedium   = lipgloss.Color("#FFCC00")
	colorLow      = lipgloss.Color("#0088FF")
	colorInfo     = lipgloss.Color("#888888")
	colorSuccess  = lipgloss.Color("#00CC00")
	colorError    = lipgloss.Color("#FF4444")
	colorMalware  = lipgloss.Color("#FF00FF")
	colorMuted    = lipgloss.Color("#666666")
	colorAccent   = lipgloss.Color("#00CCFF")
	colorWhite    = lipgloss.Color("#FFFFFF")

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
