package scan

import "testing"

// The blocking contract of the EOL gate.
//
// Grading arrived with a CLI release, not with any org's decision to adopt it. So
// the default floor must reproduce exactly what failed a build BEFORE grading
// existed: components already past their end-of-life date, and nothing else. If
// this test ever goes red, an upgrade of the CLI is about to turn "your runtime
// dies next quarter" into a red build for every customer who passes --block-eol,
// and a gate that does that gets switched off — which protects nobody.
//
// cmd/scan.go holds the floor (`eolBlockSeverity`, default "critical") and calls
// SeverityMeetsThreshold with it. This test pins the two halves that decide the
// outcome: the horizon-to-severity mapping, and whether that severity clears the
// default floor.
func TestDefaultFloorBlocksRetiredOnly(t *testing.T) {
	const defaultFloor = "critical" // cmd.eolBlockSeverity

	buckets := DefaultEOLSeverityBuckets()

	tests := []struct {
		name        string
		horizon     EOLHorizon
		wantBlocked bool
	}{
		{"already past its EOL date fails the build, as it always did", EOLRetired, true},
		{"dying within 30 days is reported, not blocked", EOLWithin30Days, false},
		{"dying this quarter is reported, not blocked", EOLThisQuarter, false},
		{"dying next quarter is reported, not blocked", EOLNextQuarter, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			severity, graded := buckets.SeverityFor(tc.horizon)
			if !graded {
				t.Fatalf("horizon %q produced no severity at all", tc.horizon)
			}

			blocked := SeverityMeetsThreshold(severity, defaultFloor)
			if blocked != tc.wantBlocked {
				t.Errorf("horizon %q graded %q: blocked=%v, want %v", tc.horizon, severity, blocked, tc.wantBlocked)
			}
		})
	}
}

// Lowering the floor is how an org opts INTO the stricter behaviour. It must
// actually work, or the setting is decoration.
func TestLoweringTheFloorBlocksMore(t *testing.T) {
	buckets := DefaultEOLSeverityBuckets()

	within30, _ := buckets.SeverityFor(EOLWithin30Days) // "high"
	nextQuarter, _ := buckets.SeverityFor(EOLNextQuarter)

	if !SeverityMeetsThreshold(within30, "high") {
		t.Error("floor=high must block a component dying within 30 days")
	}
	if SeverityMeetsThreshold(nextQuarter, "high") {
		t.Error("floor=high must NOT block a component dying next quarter")
	}
	if !SeverityMeetsThreshold(nextQuarter, "low") {
		t.Error("floor=low must block everything graded, including next quarter")
	}
}
