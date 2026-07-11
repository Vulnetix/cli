package analyze

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The complexity trend is gitvoyant's idea with gitvoyant's two bugs removed. These tests are
// the removal.

// gitvoyant regresses against the commit *index* and reports the slope as "per month". For a
// file with ten commits in one afternoon and one a year later, that number is meaningless. We
// regress against elapsed time, so the same file gives the same answer no matter how its
// commits are clustered.
func TestFitPerDay_RegressesAgainstTimeNotCommitIndex(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Complexity climbs by exactly 1 per day, sampled evenly.
	even := []trendPoint{
		{at: base, complexity: 10, sha: "a"},
		{at: base.AddDate(0, 0, 10), complexity: 20, sha: "b"},
		{at: base.AddDate(0, 0, 20), complexity: 30, sha: "c"},
		{at: base.AddDate(0, 0, 30), complexity: 40, sha: "d"},
	}
	slope, r2 := fitPerDay(even)
	require.InDelta(t, 1.0, slope, 0.001, "10 complexity per 10 days is 1 per day")
	require.InDelta(t, 1.0, r2, 0.001, "the points are exactly on the line")

	// The same trajectory, but the commits are clustered: three in one afternoon, one a month
	// later. Regressed against the commit index this looks like a cliff. Against time, it is the
	// same gentle climb — because it is.
	clustered := []trendPoint{
		{at: base, complexity: 10, sha: "a"},
		{at: base.Add(1 * time.Hour), complexity: 10, sha: "b"},
		{at: base.Add(2 * time.Hour), complexity: 10, sha: "c"},
		{at: base.AddDate(0, 0, 30), complexity: 40, sha: "d"},
	}
	slope, _ = fitPerDay(clustered)
	require.Greater(t, slope, 0.5, "still roughly 1 per day")
	require.Less(t, slope, 1.5, "and not a cliff — which is what a per-commit slope would report")
}

// gitvoyant's "confidence" is a step function of the commit count: 0.9 if there are ten
// commits, 0.75 if seven. That says nothing about whether the points lie on the line. R² does.
func TestFitPerDay_RSquaredSeparatesATrendFromNoise(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	noisy := []trendPoint{
		{at: base, complexity: 10},
		{at: base.AddDate(0, 0, 10), complexity: 50},
		{at: base.AddDate(0, 0, 20), complexity: 12},
		{at: base.AddDate(0, 0, 30), complexity: 48},
		{at: base.AddDate(0, 0, 40), complexity: 11},
	}
	_, r2 := fitPerDay(noisy)
	require.Less(t, r2, 0.5,
		"a file that swings wildly has no trend, and a low R² is what stops us sending somebody to refactor it")

	flat := []trendPoint{
		{at: base, complexity: 20},
		{at: base.AddDate(0, 0, 10), complexity: 20},
		{at: base.AddDate(0, 0, 20), complexity: 20},
	}
	slope, r2 := fitPerDay(flat)
	require.Equal(t, 0.0, slope)
	require.Equal(t, 1.0, r2, "complexity never moved; a flat line fits it perfectly")
}

func TestFitPerDay_DegenerateInputs(t *testing.T) {
	slope, r2 := fitPerDay(nil)
	require.Zero(t, slope)
	require.Zero(t, r2)

	// Every sample at the same instant: there is no time axis to regress against, and pretending
	// otherwise divides by zero and calls the result a trend.
	at := time.Now()
	same := []trendPoint{{at: at, complexity: 1}, {at: at, complexity: 99}}
	slope, r2 = fitPerDay(same)
	require.Zero(t, slope)
	require.Zero(t, r2)
}

// versionsBehind is not "how many releases exist". A package pinned to the newest version is
// zero behind however long its release history is.
func TestVersionsBehind(t *testing.T) {
	// Newest first, as the registry returns them.
	ins := PackageInsight{
		Versions: []VersionStamp{
			{Version: "2.0.0"},
			{Version: "1.9.0"},
			{Version: "1.8.0"},
			{Version: "1.7.0"},
			{Version: "1.6.0"},
		},
		LatestVersion: "2.0.0",
		Recommended:   "2.0.0",
	}

	require.Equal(t, 0, versionsBehind(ins, "2.0.0"), "pinned to the recommendation")
	require.Equal(t, 1, versionsBehind(ins, "1.9.0"))
	require.Equal(t, 4, versionsBehind(ins, "1.6.0"))

	// A version newer than the recommendation is not "behind" by a negative amount.
	ahead := ins
	ahead.Recommended = "1.8.0"
	require.Equal(t, 0, versionsBehind(ahead, "2.0.0"))

	// Unknown is -1, not 0. Reporting an unknown as "up to date" is the failure this whole
	// format exists to prevent.
	require.Equal(t, -1, versionsBehind(ins, "0.0.1-nonexistent"))
	require.Equal(t, -1, versionsBehind(PackageInsight{}, "1.0.0"))
	require.Equal(t, -1, versionsBehind(ins, ""))
}

// Without credentials, staleness is unknown — never zero. "Nothing is stale" is a claim an
// unauthenticated run has not earned.
func TestEnrichDependencies_UnauthenticatedIsUnmeasuredNotZero(t *testing.T) {
	b := newTestBuilder()
	deps := &depStats{deps: []*DependencyRecord{
		{ID: "dep-1", Type: "dependency", Purl: "pkg:golang/example.com/x@1.0.0"},
	}}

	enrichDependencies(b, deps, nil, time.Now())

	r, _, err := b.Finish(time.Now())
	require.NoError(t, err)

	found := false
	for _, m := range r.Metrics {
		if m.ID == "business.dependencies.stale" {
			found = true
			require.Nil(t, m.Value, "unknown is null, not zero")
			require.Empty(t, m.EvidenceRefs)
		}
	}
	require.True(t, found)
	require.NotEmpty(t, r.Diagnostics, "and the reason it is unknown is recorded")
}

func TestEnrichDependencies_ComputesStaleness(t *testing.T) {
	b := newTestBuilder()
	deps := &depStats{deps: []*DependencyRecord{
		{ID: "dep-current", Type: "dependency", Purl: "pkg:npm/current@2.0.0", ResolvedVersion: "2.0.0"},
		{ID: "dep-stale", Type: "dependency", Purl: "pkg:npm/stale@1.0.0", ResolvedVersion: "1.0.0"},
	}}

	// The dependency records must exist for the metrics to cite them, exactly as the dependency
	// collector would have added them.
	for _, d := range deps.deps {
		b.AddRecord(d.ID, d)
	}

	enrich := func(purls []string) (map[string]PackageInsight, error) {
		return map[string]PackageInsight{
			"pkg:npm/current@2.0.0": {
				Purl:          "pkg:npm/current@2.0.0",
				Versions:      []VersionStamp{{Version: "2.0.0"}},
				LatestVersion: "2.0.0", Recommended: "2.0.0",
			},
			"pkg:npm/stale@1.0.0": {
				Purl: "pkg:npm/stale@1.0.0",
				Versions: []VersionStamp{
					{Version: "1.5.0"}, {Version: "1.4.0"}, {Version: "1.3.0"},
					{Version: "1.2.0"}, {Version: "1.1.0"}, {Version: "1.0.0"},
				},
				LatestVersion: "1.5.0", Recommended: "1.5.0",
			},
		}, nil
	}

	enrichDependencies(b, deps, enrich, time.Now())

	r, _, err := b.Finish(time.Now())
	require.NoError(t, err)

	for _, m := range r.Metrics {
		if m.ID == "business.dependencies.stale" {
			require.Equal(t, float64(1), m.Value, "only the one that is 5 releases behind")
			require.Len(t, m.EvidenceRefs, 1)
			require.Equal(t, "dep-stale", m.EvidenceRefs[0].RecordID,
				"and the evidence names which dependency, so the number opens into a list")
		}
	}
}
