package sast

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

// Batching per-file rules is a scheduling change: the embedded rules over the
// fixture app must report exactly what one whole-scope evaluation reports,
// with batches small enough that every group splits.
func TestBatchedEvaluationParity(t *testing.T) {
	if testing.Short() {
		t.Skip("evaluates every embedded rule twice")
	}
	root := filepath.Join("..", "..", "testdata", "vulnetix-fixture-app")
	if _, err := os.Stat(filepath.Join(root, "src", "vuln.go")); err != nil {
		t.Skip("fixture app submodule not checked out")
	}
	modules, err := LoadAllModules(DefaultRulesFS, false, nil, "", io.Discard)
	require.NoError(t, err)

	run := func(batching bool, bytes, workers int) *SASTReport {
		t.Helper()
		oldB, oldBytes := perFileBatching, batchBytes
		perFileBatching, batchBytes = batching, bytes
		t.Cleanup(func() { perFileBatching, batchBytes = oldB, oldBytes })
		t.Setenv("VULNETIX_SAST_WORKERS", itoa(workers))
		rep, err := NewEngine(modules, root).Evaluate(EvalOptions{MaxDepth: 8})
		require.NoError(t, err)
		return rep
	}

	whole := run(false, 2<<20, runtime.GOMAXPROCS(0))
	batched := run(true, 4<<10, runtime.GOMAXPROCS(0))
	serial := run(true, 4<<10, 1)

	require.NotEmpty(t, whole.Findings, "the fixture app must produce findings for this test to mean anything")
	require.Equal(t, findingKeys(whole.Findings), findingKeys(batched.Findings))
	require.Equal(t, findingKeys(whole.Findings), findingKeys(serial.Findings))
	require.Equal(t, ruleIDs(whole.Rules), ruleIDs(batched.Rules), "each rule's metadata is reported once")
}

func TestFileBatches(t *testing.T) {
	in := &ScanInput{FileContents: map[string]string{
		"a": "1234", "b": "12", "c": "123456789", "d": "1",
	}}
	require.Equal(t, [][]string{{"a", "b"}, {"c"}, {"d"}}, fileBatches(in, 6))
	require.Equal(t, [][]string{{"a", "b", "c", "d"}}, fileBatches(in, 100))
	require.Equal(t, [][]string{nil}, fileBatches(&ScanInput{}, 100), "an empty scope still evaluates once")
}

func TestPerFileShards(t *testing.T) {
	require.Equal(t, 1, perFileShards(1000, 40, batchBytes, 16), "enough batches to go round: no split")
	require.Equal(t, 16, perFileShards(1000, 1, 1000, 16), "one batch is split across every worker")
	require.Equal(t, 4, perFileShards(1000, 4, 1000, 16))
	require.Equal(t, 6, perFileShards(1000, 40, 6*batchBytes, 4*4), "a file six batches long is cut six ways")
	require.Equal(t, 2, perFileShards(70, 1, 1000, 16), "never below perFileShardMinRules rules a shard")
	require.Equal(t, 1, perFileShards(10, 1, 1000, 16))
	require.Equal(t, 1, perFileShards(1000, 1, 1000, 1), "one worker, one shard")
}

func findingKeys(fs []Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.RuleID + "|" + f.ArtifactURI + "|" + itoa(f.StartLine) + "|" + f.Message + "|" + f.Snippet
	}
	return out
}

func ruleIDs(rs []RuleMetadata) map[string]int {
	out := map[string]int{}
	for _, r := range rs {
		out[r.ID]++
	}
	return out
}

func itoa(n int) string { return strconv.Itoa(n) }
