package display

import (
	"math"
	"testing"
)

func TestFormatNumber(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{123, "123"},
		{1234, "1,234"},
		{1234567, "1,234,567"},
		{1000000000, "1,000,000,000"},
		{-1234, "-1,234"},
		{-1, "-1"},
	}
	for _, tc := range tests {
		got := FormatNumber(tc.input)
		if got != tc.expected {
			t.Errorf("FormatNumber(%d): expected %q, got %q", tc.input, tc.expected, got)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		seconds  int
		expected string
	}{
		{0, "0s"},
		{30, "30s"},
		{59, "59s"},
		{60, "1m"},
		{90, "1m30s"},
		{3600, "1h"},
		{3660, "1h1m"},
		{7200, "2h"},
		{7265, "2h1m"},
	}
	for _, tc := range tests {
		got := FormatDuration(tc.seconds)
		if got != tc.expected {
			t.Errorf("FormatDuration(%d): expected %q, got %q", tc.seconds, tc.expected, got)
		}
	}
}

func TestToIntVal(t *testing.T) {
	tests := []struct {
		input    any
		expected int
	}{
		{float64(42), 42},
		{int(42), 42},
		{int64(42), 42},
		{"string", 0},
		{nil, 0},
	}
	for _, tc := range tests {
		got := ToIntVal(tc.input)
		if got != tc.expected {
			t.Errorf("ToIntVal(%v): expected %d, got %d", tc.input, tc.expected, got)
		}
	}
}

func TestToFloat64(t *testing.T) {
	tests := []struct {
		input    any
		expected float64
	}{
		{float64(3.14), 3.14},
		{int(3), 3.0},
		{int64(3), 3.0},
		{"string", 0},
		{nil, 0},
	}
	for _, tc := range tests {
		got := ToFloat64(tc.input)
		if got != tc.expected {
			t.Errorf("ToFloat64(%v): expected %f, got %f", tc.input, tc.expected, got)
		}
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		s        string
		max      int
		expected string
	}{
		{"hello", 10, "hello"},
		{"hello world", 8, "hello..."},
		{"abc", 3, "abc"},
		{"abc", 2, "abc"},
	}
	for _, tc := range tests {
		got := Truncate(tc.s, tc.max)
		if got != tc.expected {
			t.Errorf("Truncate(%q, %d): expected %q, got %q", tc.s, tc.max, tc.expected, got)
		}
	}
}

func TestPercentage(t *testing.T) {
	tests := []struct {
		n, total int
		expected string
	}{
		{0, 100, "0.0%"},
		{50, 100, "50.0%"},
		{1, 3, "33.3%"},
		{2, 3, "66.7%"},
		{0, 0, "0.0%"},
	}
	for _, tc := range tests {
		got := Percentage(tc.n, tc.total)
		if got != tc.expected {
			t.Errorf("Percentage(%d, %d): expected %q, got %q", tc.n, tc.total, tc.expected, got)
		}
	}
}

func TestRelativeTime(t *testing.T) {
	if got := RelativeTime(0); got != "unknown" {
		t.Errorf("RelativeTime(0): expected 'unknown', got %q", got)
	}
}

func TestFormatFloat(t *testing.T) {
	tests := []struct {
		f        float64
		decimals int
		expected string
	}{
		{3.14159, 2, "3.14"},
		{3.14159, 4, "3.1416"},
		{1.0, 0, "1"},
		{0.0, 2, "0.00"},
	}
	for _, tc := range tests {
		got := FormatFloat(tc.f, tc.decimals)
		if got != tc.expected {
			t.Errorf("FormatFloat(%f, %d): expected %q, got %q", tc.f, tc.decimals, tc.expected, got)
		}
	}
}

func TestPadRight(t *testing.T) {
	tests := []struct {
		s        string
		width    int
		expected string
	}{
		{"hi", 5, "hi   "},
		{"hello", 5, "hello"},
		{"hello", 3, "hello"},
	}
	for _, tc := range tests {
		got := PadRight(tc.s, tc.width)
		if got != tc.expected {
			t.Errorf("PadRight(%q, %d): expected %q, got %q", tc.s, tc.width, tc.expected, got)
		}
	}
}

func TestPadLeft(t *testing.T) {
	tests := []struct {
		s        string
		width    int
		expected string
	}{
		{"hi", 5, "   hi"},
		{"hello", 5, "hello"},
		{"hello", 3, "hello"},
	}
	for _, tc := range tests {
		got := PadLeft(tc.s, tc.width)
		if got != tc.expected {
			t.Errorf("PadLeft(%q, %d): expected %q, got %q", tc.s, tc.width, tc.expected, got)
		}
	}
}

func TestMax(t *testing.T) {
	if got := Max(3, 5); got != 5 {
		t.Errorf("Max(3,5): expected 5, got %d", got)
	}
	if got := Max(5, 3); got != 5 {
		t.Errorf("Max(5,3): expected 5, got %d", got)
	}
	if got := Max(-1, -2); got != -1 {
		t.Errorf("Max(-1,-2): expected -1, got %d", got)
	}
	if got := Max(0, 0); got != 0 {
		t.Errorf("Max(0,0): expected 0, got %d", got)
	}
}

func TestMin(t *testing.T) {
	if got := Min(3, 5); got != 3 {
		t.Errorf("Min(3,5): expected 3, got %d", got)
	}
	if got := Min(5, 3); got != 3 {
		t.Errorf("Min(5,3): expected 3, got %d", got)
	}
	if got := Min(-1, -2); got != -2 {
		t.Errorf("Min(-1,-2): expected -2, got %d", got)
	}
	if got := Min(0, 0); got != 0 {
		t.Errorf("Min(0,0): expected 0, got %d", got)
	}
}

func TestRoundFloat(t *testing.T) {
	tests := []struct {
		f        float64
		n        int
		expected float64
	}{
		{1.2345, 2, 1.23},
		{1.235, 2, 1.24},
		{1.0, 2, 1.0},
		{0.0, 0, 0.0},
	}
	for _, tc := range tests {
		got := RoundFloat(tc.f, tc.n)
		if math.Abs(got-tc.expected) > 0.001 {
			t.Errorf("RoundFloat(%f, %d): expected %f, got %f", tc.f, tc.n, tc.expected, got)
		}
	}
}

func TestToStringVal(t *testing.T) {
	tests := []struct {
		input    any
		expected string
	}{
		{"hello", "hello"},
		{nil, ""},
		{42, "42"},
		{3.14, "3.14"},
		{true, "true"},
	}
	for _, tc := range tests {
		got := ToStringVal(tc.input)
		if got != tc.expected {
			t.Errorf("ToStringVal(%v): expected %q, got %q", tc.input, tc.expected, got)
		}
	}
}

func TestToMap(t *testing.T) {
	type testStruct struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}
	got := ToMap(testStruct{Name: "test", Value: 42})
	if got == nil {
		t.Fatal("expected non-nil map")
	}
	if got["name"] != "test" {
		t.Errorf("expected name=test, got %v", got["name"])
	}
	if v, ok := got["value"].(float64); !ok || int(v) != 42 {
		t.Errorf("expected value=42, got %v", got["value"])
	}
}
