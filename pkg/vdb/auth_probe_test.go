package vdb

import (
	"testing"
	"time"
)

// The GCVE endpoint the auth probe hits rejects any month after the current one
// on the server's UTC clock, so the probe month must never be the caller's local
// month.
func TestAuthProbeMonth(t *testing.T) {
	aest := time.FixedZone("AEST", 10*3600)

	tests := []struct {
		name      string
		now       time.Time
		wantYear  int
		wantMonth int
	}{
		{
			// The reported failure: local date already 1 Aug in AEST while the
			// server is still on 31 Jul UTC.
			name:      "local date ahead of UTC across a month boundary",
			now:       time.Date(2026, 8, 1, 9, 47, 0, 0, aest),
			wantYear:  2026,
			wantMonth: 6,
		},
		{
			name:      "mid-month",
			now:       time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC),
			wantYear:  2026,
			wantMonth: 7,
		},
		{
			// AddDate on the day-of-month would overflow here: 31 Mar minus one
			// month is 31 Feb, which normalises forward to 3 Mar and yields
			// March again.
			name:      "31st of a month following a short month",
			now:       time.Date(2026, 3, 31, 23, 59, 0, 0, time.UTC),
			wantYear:  2026,
			wantMonth: 2,
		},
		{
			name:      "31 May steps back to April, not May",
			now:       time.Date(2026, 5, 31, 0, 0, 0, 0, time.UTC),
			wantYear:  2026,
			wantMonth: 4,
		},
		{
			name:      "January wraps to the previous December",
			now:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			wantYear:  2025,
			wantMonth: 12,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			year, month := authProbeMonth(tc.now)
			if year != tc.wantYear || month != tc.wantMonth {
				t.Errorf("authProbeMonth(%s) = %d/%d, want %d/%d",
					tc.now.Format(time.RFC3339), year, month, tc.wantYear, tc.wantMonth)
			}
		})
	}
}

// Whatever the local clock says, the probe month must be one the server will
// accept: strictly before the current UTC month.
func TestAuthProbeMonthNeverInFuture(t *testing.T) {
	utcNow := time.Now().UTC()
	current := time.Date(utcNow.Year(), utcNow.Month(), 1, 0, 0, 0, 0, time.UTC)

	for offset := -14 * 3600; offset <= 14*3600; offset += 3600 {
		zone := time.FixedZone("test", offset)
		// Probe every day of the year in this zone so month boundaries are hit
		// from both sides.
		for day := 0; day < 366; day++ {
			local := utcNow.In(zone).AddDate(0, 0, day)
			year, month := authProbeMonth(local)
			probe := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC)
			// The probe is only valid against a server whose clock matches ours,
			// so only assert for dates that have actually arrived.
			if local.UTC().After(utcNow) {
				continue
			}
			if !probe.Before(current) {
				t.Fatalf("probe month %d/%d for local time %s is not before the current UTC month %s",
					year, month, local.Format(time.RFC3339), current.Format("2006-01"))
			}
		}
	}
}
