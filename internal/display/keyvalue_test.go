package display

import (
	"testing"
)

func TestKeyValue_Basic(t *testing.T) {
	term := NewTerminal()
	pairs := []KVPair{
		{Key: "Name", Value: "test"},
		{Key: "Version", Value: "1.0.0"},
	}
	result := KeyValue(term, pairs)
	if result == "" {
		t.Error("expected non-empty keyvalue output")
	}
}

func TestKeyValue_Empty(t *testing.T) {
	term := NewTerminal()
	result := KeyValue(term, nil)
	if result != "" {
		t.Errorf("expected empty for nil pairs, got %q", result)
	}
}

func TestKeyValue_WithStyle(t *testing.T) {
	term := NewTerminal()
	pairs := []KVPair{
		{Key: "Severity", Value: "critical", ValueStyle: func(s string) string { return s }},
	}
	result := KeyValue(term, pairs)
	if result == "" {
		t.Error("expected non-empty keyvalue output")
	}
}

func TestKeyValue_BlankSeparator(t *testing.T) {
	term := NewTerminal()
	pairs := []KVPair{
		{Key: "A", Value: "1"},
		{Key: "", Value: ""},
		{Key: "B", Value: "2"},
	}
	result := KeyValue(term, pairs)
	if result == "" {
		t.Error("expected non-empty keyvalue output with separator")
	}
}

func TestKeyValueCompact(t *testing.T) {
	term := NewTerminal()
	pairs := []KVPair{
		{Key: "Name", Value: "test"},
	}
	result := KeyValueCompact(term, pairs)
	if result == "" {
		t.Error("expected non-empty keyvalue compact output")
	}
}
