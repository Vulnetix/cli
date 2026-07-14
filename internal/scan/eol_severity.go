package scan

import (
	"strings"
	"time"
)

// Grading end-of-life by how close it is.
//
// `--block-eol` on its own is binary: anything past its end-of-life date fails the
// build, and anything not yet past it is invisible. That is a poor fit for how
// teams actually plan. A runtime that went EOL two years ago and one that goes EOL
// next quarter are not the same problem, and a gate that cannot tell them apart
// gets switched off.
//
// So an EOL horizon maps to a synthetic severity, and the org chooses the mapping:
//
//	retired        already past its EOL date          default: critical
//	within30Days   EOL within the next 30 days        default: high
//	thisQuarter    EOL within the current quarter     default: medium
//	nextQuarter    EOL within the following quarter   default: low
//
// Any bucket may be set to "skip", which means exactly that: an org that does not
// care about next quarter's EOLs sets nextQuarter=skip and stops hearing about them.
//
// The mapping lives in CliQualityGateConfig (columns eolRetiredSeverity,
// eolWithin30DaysSeverity, eolThisQuarterSeverity, eolNextQuarterSeverity) and is
// fetched with the rest of the org policy. Those columns have existed, with these
// defaults, since the quality-gate table was created — but nothing ever read them,
// because nothing ever created a config row for any org to read. Seeding fixed the
// latter; this reads them.
//
// See https://github.com/vulnetix/cli/blob/main/.repo/policy-fetch.md

// EOLHorizon is how far away an end-of-life date is.
type EOLHorizon string

const (
	// EOLRetired is already past.
	EOLRetired EOLHorizon = "retired"

	// EOLWithin30Days is imminent.
	EOLWithin30Days EOLHorizon = "within-30-days"

	// EOLThisQuarter falls in the current calendar quarter.
	EOLThisQuarter EOLHorizon = "this-quarter"

	// EOLNextQuarter falls in the following calendar quarter.
	EOLNextQuarter EOLHorizon = "next-quarter"

	// EOLBeyond is further out than we grade, or has no date at all.
	EOLBeyond EOLHorizon = ""
)

// SeveritySkip is the bucket value that means "do not report this horizon".
const SeveritySkip = "skip"

// EOLSeverityBuckets maps each horizon to a severity. Zero values mean the org has
// not set that bucket, and the default applies.
type EOLSeverityBuckets struct {
	Retired      string
	Within30Days string
	ThisQuarter  string
	NextQuarter  string
}

// DefaultEOLSeverityBuckets mirrors the column defaults in CliQualityGateConfig, so
// an org that has never touched the setting behaves the same whether its policy was
// fetched or not.
func DefaultEOLSeverityBuckets() EOLSeverityBuckets {
	return EOLSeverityBuckets{
		Retired:      "critical",
		Within30Days: "high",
		ThisQuarter:  "medium",
		NextQuarter:  "low",
	}
}

// EOLHorizonOf classifies an end-of-life date relative to now.
//
// The date is whatever the VDB EOL API returned — an ISO date ("2026-04-30") or a
// full timestamp. An unparseable or empty date is EOLBeyond rather than an error:
// a scan must not fail because a third-party EOL feed printed a date oddly.
func EOLHorizonOf(eolFrom string, now time.Time) EOLHorizon {
	eol, ok := parseEOLDate(eolFrom)
	if !ok {
		return EOLBeyond
	}

	if !eol.After(now) {
		return EOLRetired
	}
	if !eol.After(now.AddDate(0, 0, 30)) {
		return EOLWithin30Days
	}
	if eol.Before(quarterStart(now).AddDate(0, 3, 0)) {
		return EOLThisQuarter
	}
	if eol.Before(quarterStart(now).AddDate(0, 6, 0)) {
		return EOLNextQuarter
	}

	return EOLBeyond
}

// SeverityFor maps a horizon to the severity the org assigned it. It reports
// ok=false when the horizon is not graded, or when the org set that bucket to
// "skip" — in both cases the item is not a finding at all.
func (b EOLSeverityBuckets) SeverityFor(h EOLHorizon) (string, bool) {
	defaults := DefaultEOLSeverityBuckets()

	var severity, fallback string
	switch h {
	case EOLRetired:
		severity, fallback = b.Retired, defaults.Retired
	case EOLWithin30Days:
		severity, fallback = b.Within30Days, defaults.Within30Days
	case EOLThisQuarter:
		severity, fallback = b.ThisQuarter, defaults.ThisQuarter
	case EOLNextQuarter:
		severity, fallback = b.NextQuarter, defaults.NextQuarter
	default:
		return "", false
	}

	severity = strings.ToLower(strings.TrimSpace(severity))
	if severity == "" {
		severity = fallback
	}
	if severity == SeveritySkip {
		return "", false
	}

	return severity, true
}

// parseEOLDate accepts the shapes the EOL feeds actually emit.
func parseEOLDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{"2006-01-02", time.RFC3339, "2006-01-02T15:04:05Z", "2006/01/02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}

	return time.Time{}, false
}

// quarterStart is the first day of the calendar quarter containing t.
func quarterStart(t time.Time) time.Time {
	month := ((int(t.Month()) - 1) / 3 * 3) + 1

	return time.Date(t.Year(), time.Month(month), 1, 0, 0, 0, 0, t.Location())
}
