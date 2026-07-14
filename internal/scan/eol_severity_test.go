package scan

import (
	"testing"
	"time"
)

// now is mid-Q1 so "this quarter" and "next quarter" are unambiguous.
var now = time.Date(2026, time.February, 10, 0, 0, 0, 0, time.UTC)

func TestEOLHorizonOf(t *testing.T) {
	tests := []struct {
		name    string
		eolFrom string
		want    EOLHorizon
	}{
		{"already past", "2024-01-01", EOLRetired},
		{"today is not a reprieve", "2026-02-10", EOLRetired},
		{"imminent", "2026-03-01", EOLWithin30Days},
		{"exactly 30 days out is still imminent", "2026-03-12", EOLWithin30Days},
		{"later in this quarter", "2026-03-20", EOLThisQuarter},
		{"next quarter", "2026-05-15", EOLNextQuarter},
		{"beyond next quarter is not graded", "2026-11-01", EOLBeyond},
		{"no date at all", "", EOLBeyond},
		// A third-party feed printing a date oddly must not fail the scan.
		{"unparseable date", "sometime next year", EOLBeyond},
		{"full timestamp", "2024-06-01T00:00:00Z", EOLRetired},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := EOLHorizonOf(tc.eolFrom, now); got != tc.want {
				t.Errorf("EOLHorizonOf(%q) = %q, want %q", tc.eolFrom, got, tc.want)
			}
		})
	}
}

func TestSeverityForUsesTheDefaults(t *testing.T) {
	var unset EOLSeverityBuckets // an org that has never touched the setting

	tests := []struct {
		horizon EOLHorizon
		want    string
	}{
		{EOLRetired, "critical"},
		{EOLWithin30Days, "high"},
		{EOLThisQuarter, "medium"},
		{EOLNextQuarter, "low"},
	}

	for _, tc := range tests {
		got, ok := unset.SeverityFor(tc.horizon)
		if !ok || got != tc.want {
			t.Errorf("SeverityFor(%q) = (%q, %v), want (%q, true)", tc.horizon, got, ok, tc.want)
		}
	}

	if _, ok := unset.SeverityFor(EOLBeyond); ok {
		t.Error("an ungraded horizon must not produce a finding")
	}
}

func TestSeverityForHonoursTheOrgsChoices(t *testing.T) {
	b := EOLSeverityBuckets{
		Retired:      "high",
		Within30Days: "medium",
		ThisQuarter:  SeveritySkip, // "stop telling me about this quarter"
		NextQuarter:  SeveritySkip,
	}

	if got, _ := b.SeverityFor(EOLRetired); got != "high" {
		t.Errorf("retired = %q, want the org's own value 'high'", got)
	}
	if _, ok := b.SeverityFor(EOLThisQuarter); ok {
		t.Error("a bucket set to skip must produce no finding at all")
	}
	if _, ok := b.SeverityFor(EOLNextQuarter); ok {
		t.Error("a bucket set to skip must produce no finding at all")
	}
}

// The whole point of grading: a runtime that went EOL two years ago and one that
// goes EOL next quarter are not the same problem, and a gate that cannot tell them
// apart gets switched off.
func TestGradingSeparatesLongDeadFromMerelyApproaching(t *testing.T) {
	b := DefaultEOLSeverityBuckets()

	long, _ := b.SeverityFor(EOLHorizonOf("2023-01-01", now))
	soon, _ := b.SeverityFor(EOLHorizonOf("2026-05-15", now))

	if long == soon {
		t.Fatalf("a two-years-dead runtime and a next-quarter one both graded %q", long)
	}
	if long != "critical" || soon != "low" {
		t.Fatalf("graded long-dead=%q next-quarter=%q, want critical/low", long, soon)
	}
}
