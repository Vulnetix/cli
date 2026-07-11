package analyze

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A nil Reporter is valid, so every collector can call it unconditionally.
func TestReporter_NilIsANoOp(t *testing.T) {
	var pr reporter
	require.NotPanics(t, func() {
		pr.Stage("working")
		pr.Step(1, "done")
	})
}

// The step constants must be in the order Run executes them. A step number lower than the one
// before it makes the bar run backwards, which reads as a bug in the tool rather than a bug in
// the numbering — and it did, until this test.
func TestStepOrderMatchesExecution(t *testing.T) {
	// The order Run actually calls them in.
	execution := []int{
		stepGit,
		stepFiles,
		stepDeps,
		stepEnrich,
		stepTrust,
		stepCoupling,
		stepTrend,
		stepSymbols,
		stepContracts,
		stepForge,
		stepReport,
	}

	for i, step := range execution {
		require.Equal(t, i+1, step,
			"step %d is out of order: the progress bar would jump backwards here", i+1)
	}

	require.Equal(t, len(execution), TotalSteps,
		"TotalSteps must equal the number of steps, or the bar never reaches 100%%")
}

func TestPlural(t *testing.T) {
	require.Equal(t, "1 commit", plural(1, "commit", "commits"), `"1 commits" reads like a bug`)
	require.Equal(t, "2 commits", plural(2, "commit", "commits"))
	require.Equal(t, "0 commits", plural(0, "commit", "commits"))
	require.Equal(t, "1,500 commits", plural(1500, "commit", "commits"))
}

// A progress line saying "walking 148293 commits" makes the reader do arithmetic to find out
// whether that is a lot.
func TestCommas(t *testing.T) {
	require.Equal(t, "0", commas(0))
	require.Equal(t, "999", commas(999))
	require.Equal(t, "1,000", commas(1000))
	require.Equal(t, "12,345", commas(12345))
	require.Equal(t, "148,293", commas(148293))
	require.Equal(t, "1,234,567", commas(1234567))
	require.Equal(t, "0", commas(-5))
}
