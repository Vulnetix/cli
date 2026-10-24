package fix

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

func TestResolveTargetStableClosestSafeNoDowngrade(t *testing.T) {
	target, decision := ResolveTarget("1.2.0", StrategyStable, nil, []vdb.CliSafeHarbourVersion{
		{Version: "1.1.9"},
		{Version: "1.2.3"},
		{Version: "2.0.0"},
	}, nil, 1)
	require.False(t, decision.Skipped)
	require.Equal(t, "1.2.3", target)
}

func TestResolveTargetRejectsMajorCap(t *testing.T) {
	target, decision := ResolveTarget("1.2.0", StrategyStable, nil, []vdb.CliSafeHarbourVersion{
		{Version: "3.0.0"},
	}, nil, 0)
	require.Empty(t, target)
	require.True(t, decision.Skipped)
	require.Contains(t, decision.Reason, "major")
}

func TestResolveTargetSkipsAlreadyInstalledTarget(t *testing.T) {
	target, decision := ResolveTarget("1.2.3", StrategySafest, nil, []vdb.CliSafeHarbourVersion{{
		Version:            "1.2.3",
		VulnerabilityCount: 0,
		ExploitCount:       0,
	}}, nil, 0)

	require.Empty(t, target)
	require.True(t, decision.Skipped)
	require.Contains(t, decision.Reason, "already installed")
}

func TestResolveTargetSafestUsesHighestScoreThenNewest(t *testing.T) {
	target, decision := ResolveTarget("1.0.0", StrategySafest, nil, []vdb.CliSafeHarbourVersion{
		{Version: "1.2.0", SafeHarbourScore: 0.9},
		{Version: "1.3.0", SafeHarbourScore: 0.9},
		{Version: "2.0.0", SafeHarbourScore: 0.7},
	}, nil, 1)
	require.False(t, decision.Skipped)
	require.Equal(t, "1.3.0", target)
}

func TestSatisfiesAndBestInRange(t *testing.T) {
	require.True(t, Satisfies("1.4.2", "^1.2.0"))
	require.False(t, Satisfies("2.0.0", "^1.2.0"))
	require.Equal(t, "1.3.0", BestInRange([]string{"2.0.0", "1.3.0", "1.2.1"}, "^1.2.0"))
}

func picksSummary(p vdb.CliSafeHarbourPicks) *vdb.CliSafeHarbourSummary {
	return &vdb.CliSafeHarbourSummary{Picks: &p}
}

func TestResolveTargetUsesServerPicksPerStrategy(t *testing.T) {
	summary := picksSummary(vdb.CliSafeHarbourPicks{
		Latest:        "3.4.0",
		Safest:        "3.3.0",
		Stable:        "3.1.0",
		Rolling:       []string{"3.4.0", "3.4.0-rc.1"},
		RollingTarget: "3.4.0-rc.1",
	})
	// SafeVersions disagree with every pick, so a pass proves the picks won.
	safe := []vdb.CliSafeHarbourVersion{{Version: "3.0.5", SafeHarbourScore: 1}}
	latest := []vdb.CliVersionStamp{{Version: "9.9.9"}}

	cases := map[Strategy]string{
		StrategyLatest:  "3.4.0",
		StrategySafest:  "3.3.0",
		StrategyStable:  "3.1.0",
		StrategyRolling: "3.4.0-rc.1",
	}
	for strategy, want := range cases {
		target, decision := ResolveTarget("3.0.0", strategy, latest, safe, summary, -1)
		require.False(t, decision.Skipped, string(strategy))
		require.Empty(t, decision.Note, string(strategy))
		require.Equal(t, want, target, string(strategy))
	}
}

func TestResolveTargetLatestIsHighestStableNotNewestPublished(t *testing.T) {
	// ruff: 0.17.2 is the highest stable release, while the newest by publish
	// date was an older line's backport.
	summary := picksSummary(vdb.CliSafeHarbourPicks{Latest: "0.17.2", Safest: "0.17.2", Stable: "0.15.12"})
	latest := []vdb.CliVersionStamp{{Version: "0.15.11"}}
	target, decision := ResolveTarget("0.15.10", StrategyLatest, latest, nil, summary, -1)
	require.False(t, decision.Skipped)
	require.Equal(t, "0.17.2", target)
}

func TestResolveTargetFallsBackWhenPicksAbsent(t *testing.T) {
	safe := []vdb.CliSafeHarbourVersion{
		{Version: "1.2.3", SafeHarbourScore: 0.5},
		{Version: "2.0.0", SafeHarbourScore: 0.9},
	}
	latest := []vdb.CliVersionStamp{{Version: "2.1.0"}}

	target, _ := ResolveTarget("1.2.0", StrategyLatest, latest, safe, &vdb.CliSafeHarbourSummary{}, -1)
	require.Equal(t, "2.1.0", target)
	target, _ = ResolveTarget("1.2.0", StrategySafest, latest, safe, nil, -1)
	require.Equal(t, "2.0.0", target)
	target, _ = ResolveTarget("1.2.0", StrategyStable, latest, safe, nil, -1)
	require.Equal(t, "1.2.3", target)
}

func TestResolveTargetFallsBackWhenPickEmpty(t *testing.T) {
	summary := picksSummary(vdb.CliSafeHarbourPicks{
		Reasons: map[string]string{"safest": "every release has a known vulnerability"},
	})
	safe := []vdb.CliSafeHarbourVersion{{Version: "1.2.3"}}
	target, decision := ResolveTarget("1.2.0", StrategySafest, nil, safe, summary, -1)
	require.False(t, decision.Skipped)
	require.Equal(t, "1.2.3", target)
}

func TestResolveTargetRollingWithoutServerSupportUsesStableAndSaysSo(t *testing.T) {
	safe := []vdb.CliSafeHarbourVersion{{Version: "1.1.0"}, {Version: "1.2.3"}, {Version: "2.0.0"}}
	for name, summary := range map[string]*vdb.CliSafeHarbourSummary{
		"nil summary":  nil,
		"no picks":     {},
		"empty picks":  picksSummary(vdb.CliSafeHarbourPicks{Stable: "1.2.3"}),
		"empty picks2": picksSummary(vdb.CliSafeHarbourPicks{}),
	} {
		target, decision := ResolveTarget("1.2.0", StrategyRolling, nil, safe, summary, -1)
		require.False(t, decision.Skipped, name)
		require.Equal(t, "1.2.3", target, name)
		require.Contains(t, decision.Note, "using stable", name)
	}

	_, decision := ResolveTarget("1.2.0", StrategyRolling, nil, safe, nil, -1)
	require.Equal(t, "server did not return a rolling set; using stable", decision.Note)
}

func TestResolveTargetRollingNoteCarriesServerReason(t *testing.T) {
	summary := picksSummary(vdb.CliSafeHarbourPicks{
		Reasons: map[string]string{"rolling": "no clean version on the latest release day"},
	})
	_, decision := ResolveTarget("1.2.0", StrategyRolling, nil, []vdb.CliSafeHarbourVersion{{Version: "1.3.0"}}, summary, -1)
	require.Contains(t, decision.Note, "no clean version on the latest release day")
	require.Contains(t, decision.Note, "using stable")
}

func TestResolveTargetRollingKeepsGuards(t *testing.T) {
	summary := picksSummary(vdb.CliSafeHarbourPicks{RollingTarget: "1.2.3"})

	target, decision := ResolveTarget("1.2.3", StrategyRolling, nil, nil, summary, -1)
	require.Empty(t, target)
	require.True(t, decision.Skipped)
	require.Contains(t, decision.Reason, "already installed")

	target, decision = ResolveTarget("1.5.0", StrategyRolling, nil, nil, summary, -1)
	require.Empty(t, target)
	require.True(t, decision.Skipped)
	require.Contains(t, decision.Reason, "downgrade")

	summary = picksSummary(vdb.CliSafeHarbourPicks{RollingTarget: "4.0.0"})
	target, decision = ResolveTarget("1.5.0", StrategyRolling, nil, nil, summary, 1)
	require.Empty(t, target)
	require.True(t, decision.Skipped)
	require.Contains(t, decision.Reason, "major")
}

func TestResolveTargetServerPickKeepsGuardsForEveryStrategy(t *testing.T) {
	summary := picksSummary(vdb.CliSafeHarbourPicks{Latest: "0.17.2", Safest: "0.15.10", Stable: "0.15.10"})

	// The ruff case: running 0.15.10, the highest stable release is 0.17.2.
	target, decision := ResolveTarget("0.15.10", StrategyLatest, nil, nil, summary, -1)
	require.False(t, decision.Skipped)
	require.Equal(t, "0.17.2", target)

	for _, s := range []Strategy{StrategySafest, StrategyStable} {
		_, decision = ResolveTarget("0.15.10", s, nil, nil, summary, -1)
		require.True(t, decision.Skipped, string(s))
		require.Contains(t, decision.Reason, "already installed", string(s))
	}
}

// The major-version cap: 0 keeps the current major (the documented default),
// N allows up to N majors, and a negative value lifts the cap.
func TestResolveTargetMajorCapZeroNegativeAndN(t *testing.T) {
	safe := []vdb.CliSafeHarbourVersion{{Version: "3.1.0"}}
	_, decision := ResolveTarget("1.0.0", StrategySafest, nil, safe, nil, 0)
	require.True(t, decision.Skipped, "0 must refuse any new major")
	require.Contains(t, decision.Reason, "new major version")

	_, decision = ResolveTarget("1.0.0", StrategySafest, nil, safe, nil, 1)
	require.True(t, decision.Skipped, "1 must refuse a two-major jump")
	require.Contains(t, decision.Reason, "crosses more than 1 major version")

	target, decision := ResolveTarget("1.0.0", StrategySafest, nil, safe, nil, 2)
	require.False(t, decision.Skipped)
	require.Equal(t, "3.1.0", target)

	target, decision = ResolveTarget("1.0.0", StrategySafest, nil, safe, nil, -1)
	require.False(t, decision.Skipped, "a negative cap is no limit")
	require.Equal(t, "3.1.0", target)
}
