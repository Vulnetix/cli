package display

import (
	"testing"
)

func TestNumberedList(t *testing.T) {
	term := NewTerminal()
	items := []string{"first", "second", "third"}
	result := NumberedList(term, items)
	if result == "" {
		t.Error("expected non-empty numbered list")
	}
}

func TestNumberedList_Empty(t *testing.T) {
	term := NewTerminal()
	result := NumberedList(term, nil)
	if result != "" {
		t.Errorf("expected empty, got %q", result)
	}
}

func TestBulletList(t *testing.T) {
	term := NewTerminal()
	items := []string{"item1", "item2"}
	result := BulletList(term, items)
	if result == "" {
		t.Error("expected non-empty bullet list")
	}
}

func TestBulletList_Empty(t *testing.T) {
	term := NewTerminal()
	result := BulletList(term, nil)
	if result != "" {
		t.Errorf("expected empty, got %q", result)
	}
}

func TestPaginator(t *testing.T) {
	term := NewTerminal()
	result := Paginator(term, 100, 10, 0, true)
	if result == "" {
		t.Error("expected non-empty paginator")
	}
}

func TestPaginator_Empty(t *testing.T) {
	term := NewTerminal()
	result := Paginator(term, 0, 10, 0, false)
	if result != "" {
		t.Errorf("expected empty for 0 total, got %q", result)
	}
}

func TestCountHeader(t *testing.T) {
	term := NewTerminal()
	result := CountHeader(term, 42, "findings")
	if result == "" {
		t.Error("expected non-empty count header")
	}
}
