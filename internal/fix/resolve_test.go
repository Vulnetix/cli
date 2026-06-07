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
