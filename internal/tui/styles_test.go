package tui

import (
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func TestSeverityStyle_KnownSeverities(t *testing.T) {
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		_ = SeverityStyle(sev)
	}
}

func TestSeverityStyle_Unknown(t *testing.T) {
	_ = SeverityStyle("unknown")
	_ = SeverityStyle("")
}

func TestSeverityColor_KnownSeverities(t *testing.T) {
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		c := SeverityColor(sev)
		if c == "" {
			t.Errorf("expected non-empty color for %q", sev)
		}
	}

	c := SeverityColor("unknown")
	if c == "" {
		t.Error("expected non-empty color for unknown")
	}
	if c != colorInfo {
		t.Errorf("expected info color for unknown, got %v", c)
	}
}

func TestColors_Exported(t *testing.T) {
	colors := []lipgloss.Color{
		ColorCritical,
		ColorHigh,
		ColorMedium,
		ColorLow,
		ColorInfo,
		ColorSuccess,
		ColorError,
		ColorMalware,
		ColorMuted,
		ColorAccent,
		ColorTeal,
		ColorWhite,
	}
	for _, c := range colors {
		if c == "" {
			t.Error("expected non-empty exported color")
		}
	}
}
