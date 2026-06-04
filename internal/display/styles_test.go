package display

import (
	"testing"
)

func TestHeader(t *testing.T) {
	term := NewTerminal()
	result := Header(term, "Test Header")
	if result == "" {
		t.Error("expected non-empty header")
	}
}

func TestSubheader(t *testing.T) {
	term := NewTerminal()
	result := Subheader(term, "Sub")
	if result == "" {
		t.Error("expected non-empty subheader")
	}
}

func TestLabel(t *testing.T) {
	term := NewTerminal()
	result := Label(term, "Label:")
	if result == "" {
		t.Error("expected non-empty label")
	}
}

func TestMuted(t *testing.T) {
	term := NewTerminal()
	result := Muted(term, "dim")
	if result == "" {
		t.Error("expected non-empty muted")
	}
}

func TestBold(t *testing.T) {
	term := NewTerminal()
	result := Bold(term, "bold")
	if result == "" {
		t.Error("expected non-empty bold")
	}
}

func TestSuccess(t *testing.T) {
	term := NewTerminal()
	result := Success(term, "ok")
	if result == "" {
		t.Error("expected non-empty success")
	}
}

func TestErrorStyle(t *testing.T) {
	term := NewTerminal()
	result := ErrorStyle(term, "error")
	if result == "" {
		t.Error("expected non-empty error")
	}
}

func TestAccent(t *testing.T) {
	term := NewTerminal()
	result := Accent(term, "accent")
	if result == "" {
		t.Error("expected non-empty accent")
	}
}

func TestTeal(t *testing.T) {
	term := NewTerminal()
	result := Teal(term, "path/file.go")
	if result == "" {
		t.Error("expected non-empty teal")
	}
}

func TestSeverityBadge(t *testing.T) {
	term := NewTerminal()
	result := SeverityBadge(term, "critical")
	if result == "" {
		t.Error("expected non-empty badge")
	}
}

func TestSeverityText(t *testing.T) {
	term := NewTerminal()
	result := SeverityText(term, "high")
	if result == "" {
		t.Error("expected non-empty severity text")
	}
}

func TestDivider(t *testing.T) {
	term := NewTerminal()
	result := Divider(term)
	if result == "" {
		t.Error("expected non-empty divider")
	}
}

func TestShortDivider(t *testing.T) {
	term := NewTerminal()
	result := ShortDivider(term, 40)
	if result == "" {
		t.Error("expected non-empty short divider")
	}
}

func TestBar(t *testing.T) {
	term := NewTerminal()
	result := Bar(term, 5, 10, 10)
	if result == "" {
		t.Error("expected non-empty bar")
	}
}

func TestCheckMark(t *testing.T) {
	term := NewTerminal()
	result := CheckMark(term)
	if result == "" {
		t.Error("expected non-empty checkmark")
	}
}

func TestCrossMark(t *testing.T) {
	term := NewTerminal()
	result := CrossMark(term)
	if result == "" {
		t.Error("expected non-empty crossmark")
	}
}

func TestWarningMark(t *testing.T) {
	term := NewTerminal()
	result := WarningMark(term)
	if result == "" {
		t.Error("expected non-empty warning mark")
	}
}
