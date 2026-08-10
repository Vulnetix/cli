package sast

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/require"
)

// The language-server work in internal/lsp depends on one OPA property that is
// documented but not, until now, exercised by this repo: a single
// rego.PreparedEvalQuery, prepared once from one compiler, can be Eval'd
// concurrently from many goroutines against different inputs.
//
// Today Evaluate() calls compileModules() per shard on every call
// (engine.go:218, :255), so the ~85s compile is paid again for every scan. A
// warm daemon cannot do that. The intended replacement compiles once, calls
// PrepareForEval once per shard, and then serves every didChange/didSave from
// the prepared queries. If preparation or concurrent Eval is not safe, that
// design is wrong and the fallback is a per-shard mutex or one prepared query
// per shard per goroutine — so this must be settled before anything is built
// on top of it.
//
// Run these with -race. They are the gate on the warm-state design.

// preparedFixture builds a module set of nRules synthetic rules plus one shared
// library module, mirroring the real corpus shape: independent
// vulnetix.rules.<id> packages that each emit a `findings` set and carry a
// `metadata` object, over a shared helper package.
func preparedFixture(nRules int) map[string]string {
	modules := map[string]string{
		"lib.rego": "package vulnetix.lib\n\nimport rego.v1\n\nneedle := \"NEEDLE\"\n",
	}
	for i := range nRules {
		modules[fmt.Sprintf("rules/syn_%03d.rego", i)] = fmt.Sprintf(`package vulnetix.rules.syn_%03d

import rego.v1
import data.vulnetix.lib

metadata := {"id": "SYN-%03d", "name": "synthetic", "languages": [], "severity": "low", "level": "note", "kind": "sast"}

findings contains f if {
	some path, content in input.file_contents
	contains(content, "MARK_%03d")
	contains(content, lib.needle)
	f := {"rule_id": "SYN-%03d", "message": "hit", "artifact_uri": path, "start_line": 1}
}
`, i, i, i, i)
	}
	return modules
}

// prepare compiles modules and prepares the same query Evaluate() uses.
func prepare(t *testing.T, modules map[string]string) rego.PreparedEvalQuery {
	t.Helper()
	compiler, err := compileModules(modules)
	require.NoError(t, err)
	pq, err := rego.New(
		rego.Compiler(compiler),
		rego.Query("data.vulnetix.rules"),
	).PrepareForEval(context.Background())
	require.NoError(t, err, "PrepareForEval must succeed on a rule-corpus-shaped module set")
	return pq
}

// inputFiring builds a ScanInput whose single file fires exactly the rules
// whose index is in want.
func inputFiring(name string, want []int) *ScanInput {
	body := "NEEDLE\n"
	for _, i := range want {
		body += fmt.Sprintf("MARK_%03d\n", i)
	}
	return &ScanInput{
		FileSet:        map[string]bool{name: true},
		DirsByLanguage: map[string][]string{},
		FileContents:   map[string]string{name: body},
		ScanRoot:       "/fixture",
	}
}

// evalFingerprints runs one prepared query against one input and returns the
// findings in the same normalised form the engine produces.
func evalFingerprints(ctx context.Context, pq rego.PreparedEvalQuery, in *ScanInput) ([]string, error) {
	rs, err := pq.Eval(ctx, rego.EvalInput(in))
	if err != nil {
		return nil, err
	}
	rules, err := extractAllMetadata(rs)
	if err != nil {
		return nil, err
	}
	findings, err := extractAllFindings(rs, rules)
	if err != nil {
		return nil, err
	}
	return fingerprintSet(findings), nil
}

// TestPreparedQueryConcurrentEvalParity is the gate on the warm-state design in
// internal/sast/session.go: one prepared query, many goroutines, different
// inputs, results identical to evaluating the same inputs sequentially.
func TestPreparedQueryConcurrentEvalParity(t *testing.T) {
	const (
		nRules   = 120 // > shardMinRules, so this is a realistic shard's worth
		nWorkers = 8
	)

	pq := prepare(t, preparedFixture(nRules))
	ctx := context.Background()

	// Each worker gets a distinct, overlapping subset of rules so a torn read
	// of shared state would show up as a wrong finding set, not just a wrong
	// count. Worker w fires every rule where i%nWorkers == w, plus rule 0
	// (shared by all) and rule w (unique to it).
	inputs := make([]*ScanInput, nWorkers)
	for w := range nWorkers {
		want := []int{0, w}
		for i := range nRules {
			if i%nWorkers == w {
				want = append(want, i)
			}
		}
		inputs[w] = inputFiring(fmt.Sprintf("worker_%d.txt", w), want)
	}

	// Sequential baseline on the same prepared query.
	sequential := make([][]string, nWorkers)
	for w := range nWorkers {
		got, err := evalFingerprints(ctx, pq, inputs[w])
		require.NoError(t, err)
		require.NotEmpty(t, got, "worker %d must produce findings, or the test proves nothing", w)
		sequential[w] = got
	}

	// Concurrent run against the identical prepared query.
	concurrent := make([][]string, nWorkers)
	errs := make([]error, nWorkers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for w := range nWorkers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start // maximise overlap
			concurrent[w], errs[w] = evalFingerprints(ctx, pq, inputs[w])
		}(w)
	}
	close(start)
	wg.Wait()

	for w := range nWorkers {
		require.NoError(t, errs[w], "worker %d", w)
		require.Equal(t, sequential[w], concurrent[w],
			"worker %d: concurrent Eval on a shared PreparedEvalQuery must match the sequential result", w)
	}

	// The union must also match, which catches a cross-worker leak that
	// happened to preserve each worker's count.
	require.Equal(t, unionSorted(sequential), unionSorted(concurrent), "union across workers")
}

// TestPreparedQueryRepeatedEvalIsStable proves the prepared query is reusable:
// evaluating the same input many times returns the same result, so the daemon
// can hold one query for the life of a rule set instead of rebuilding it.
func TestPreparedQueryRepeatedEvalIsStable(t *testing.T) {
	pq := prepare(t, preparedFixture(80))
	ctx := context.Background()
	in := inputFiring("code.txt", []int{0, 1, 2, 40, 79})

	first, err := evalFingerprints(ctx, pq, in)
	require.NoError(t, err)
	require.Len(t, first, 5)

	for i := range 20 {
		got, err := evalFingerprints(ctx, pq, in)
		require.NoError(t, err, "iteration %d", i)
		require.Equal(t, first, got, "iteration %d: prepared query must be stable across reuse", i)
	}
}

// TestPreparedQueryConcurrentSameInput hammers one prepared query with the same
// input from many goroutines. Distinct inputs above prove isolation; identical
// inputs here maximise contention on any shared internal state.
func TestPreparedQueryConcurrentSameInput(t *testing.T) {
	if testing.Short() {
		t.Skip("contention stress; skipped under -short")
	}
	const nWorkers = 16

	pq := prepare(t, preparedFixture(120))
	ctx := context.Background()
	in := inputFiring("code.txt", []int{0, 5, 17, 63, 119})

	want, err := evalFingerprints(ctx, pq, in)
	require.NoError(t, err)
	require.Len(t, want, 5)

	got := make([][]string, nWorkers)
	errs := make([]error, nWorkers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for w := range nWorkers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			for range 5 {
				got[w], errs[w] = evalFingerprints(ctx, pq, in)
				if errs[w] != nil {
					return
				}
			}
		}(w)
	}
	close(start)
	wg.Wait()

	for w := range nWorkers {
		require.NoError(t, errs[w], "worker %d", w)
		require.Equal(t, want, got[w], "worker %d", w)
	}
}

// TestPreparedQueryPreservesEnginePathParity proves a prepared query returns
// what the current per-call rego.New(...).Eval() path returns, so swapping the
// engine over to prepared queries is a performance change and not a behaviour
// change.
func TestPreparedQueryPreservesEnginePathParity(t *testing.T) {
	modules := preparedFixture(120)
	in := inputFiring("code.txt", []int{0, 3, 11, 60, 119})
	ctx := context.Background()

	// Today's path: compile, then rego.New(...).Eval() with the input baked in.
	compiler, err := compileModules(modules)
	require.NoError(t, err)
	rs, err := rego.New(
		rego.Compiler(compiler),
		rego.Query("data.vulnetix.rules"),
		rego.Input(in),
	).Eval(ctx)
	require.NoError(t, err)
	rules, err := extractAllMetadata(rs)
	require.NoError(t, err)
	findings, err := extractAllFindings(rs, rules)
	require.NoError(t, err)
	current := fingerprintSet(findings)
	require.Len(t, current, 5)

	// Warm path: prepare once, pass the input at eval time.
	warm, err := evalFingerprints(ctx, prepare(t, modules), in)
	require.NoError(t, err)

	require.Equal(t, current, warm, "prepared-query results must match the current per-call Eval path")
}

func unionSorted(sets [][]string) []string {
	seen := map[string]struct{}{}
	for _, s := range sets {
		for _, v := range s {
			seen[v] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
