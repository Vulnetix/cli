package sast

import (
	"context"
	"fmt"
	"io"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func sessionFixtureInput(t *testing.T, name string, want []int) *ScanInput {
	t.Helper()
	return inputFiring(name, want)
}

// TestWarmCacheHit is the whole point of Session: the second evaluation of an
// unchanged rule set must not recompile. Engine.Evaluate recompiles per shard
// on every call, which is what makes it unusable for a process that evaluates
// on every keystroke.
func TestWarmCacheHit(t *testing.T) {
	var s Session
	ctx := context.Background()
	modules := preparedFixture(120)
	in := sessionFixtureInput(t, "code.txt", []int{0, 1, 2})

	first, err := s.Run(ctx, modules, nil, in)
	require.NoError(t, err)
	require.Len(t, first.Findings, 3)
	require.Equal(t, int64(1), s.Compiles(), "the first run must compile")

	for i := range 10 {
		got, err := s.Run(ctx, modules, nil, in)
		require.NoError(t, err, "run %d", i)
		require.Len(t, got.Findings, 3, "run %d", i)
	}
	require.Equal(t, int64(1), s.Compiles(), "warm runs must not recompile")
	require.Equal(t, 1, s.CachedSets())
}

// TestSessionParityWithEngine proves swapping the engine over to a warm session
// is a performance change and not a behaviour change.
func TestSessionParityWithEngine(t *testing.T) {
	modules := preparedFixture(120)
	in := sessionFixtureInput(t, "code.txt", []int{0, 7, 42, 119})
	ctx := context.Background()

	var s Session
	warm, err := s.Run(ctx, modules, nil, in)
	require.NoError(t, err)

	cold, err := evalModules(modules, in)
	require.NoError(t, err)

	require.Equal(t, fingerprintSet(cold.Findings), fingerprintSet(warm.Findings),
		"a warm session must return exactly what the existing per-call path returns")
	require.Equal(t, len(cold.Rules), len(warm.Rules), "rule count parity")
}

// TestChangedModulesGetANewKey covers invalidation. It is a lookup, not a
// signal: an edited rule hashes differently, so the stale entry is simply never
// found. Nothing has to observe that the pack changed.
func TestChangedModulesGetANewKey(t *testing.T) {
	var s Session
	ctx := context.Background()
	in := sessionFixtureInput(t, "code.txt", []int{0})

	modules := preparedFixture(120)
	_, err := s.Run(ctx, modules, nil, in)
	require.NoError(t, err)
	require.Equal(t, int64(1), s.Compiles())

	// Edit one rule's source.
	edited := make(map[string]string, len(modules))
	for k, v := range modules {
		edited[k] = v
	}
	edited["rules/syn_000.rego"] += "\n# a comment that changes the digest\n"

	_, err = s.Run(ctx, edited, nil, in)
	require.NoError(t, err)
	require.Equal(t, int64(2), s.Compiles(), "an edited rule set must compile afresh")
	require.Equal(t, 2, s.CachedSets(), "and both remain cached")
}

// TestKindsChangeTheKey is what lets the language server hold both the
// keystroke set (sast/iac/oci) and the save set (everything) warm at once.
func TestKindsChangeTheKey(t *testing.T) {
	var s Session
	ctx := context.Background()
	in := sessionFixtureInput(t, "code.txt", []int{0})
	modules := preparedFixture(120)

	_, err := s.Prepare(ctx, modules, InteractiveKinds)
	require.NoError(t, err)
	_, err = s.Prepare(ctx, modules, nil)
	require.NoError(t, err)
	require.Equal(t, int64(2), s.Compiles())
	require.Equal(t, 2, s.CachedSets())

	// Both stay warm; neither evicts the other.
	_, err = s.Run(ctx, modules, InteractiveKinds, in)
	require.NoError(t, err)
	_, err = s.Run(ctx, modules, nil, in)
	require.NoError(t, err)
	require.Equal(t, int64(2), s.Compiles())
}

// TestKindOrderDoesNotChangeTheKey stops an equivalent filter given in a
// different order from compiling a second identical copy.
func TestKindOrderDoesNotChangeTheKey(t *testing.T) {
	var s Session
	ctx := context.Background()
	modules := preparedFixture(120)

	_, err := s.Prepare(ctx, modules, []string{KindSAST, KindIAC, KindOCI})
	require.NoError(t, err)
	_, err = s.Prepare(ctx, modules, []string{KindOCI, KindSAST, KindIAC})
	require.NoError(t, err)

	require.Equal(t, int64(1), s.Compiles(), "the same kinds in a different order are the same set")
	require.Equal(t, 1, s.CachedSets())
}

// TestConcurrentPrepareCompilesOnce covers the cold-start case: several open
// documents all asking for the same rule set at once must produce one compile,
// not one per document.
func TestConcurrentPrepareCompilesOnce(t *testing.T) {
	var s Session
	ctx := context.Background()
	modules := preparedFixture(120)

	const n = 12
	sets := make([]*PreparedSet, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			sets[i], errs[i] = s.Prepare(ctx, modules, nil)
		}(i)
	}
	close(start)
	wg.Wait()

	for i := range n {
		require.NoError(t, errs[i], "goroutine %d", i)
		require.NotNil(t, sets[i])
		require.Same(t, sets[0], sets[i], "every caller must get the same prepared set")
	}
	require.Equal(t, int64(1), s.Compiles())
}

// TestConcurrentEvalOnOneSession is the daemon's steady state: many documents
// evaluating against one shared prepared set.
func TestConcurrentEvalOnOneSession(t *testing.T) {
	var s Session
	ctx := context.Background()
	modules := preparedFixture(120)

	set, err := s.Prepare(ctx, modules, nil)
	require.NoError(t, err)

	const n = 16
	got := make([][]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			in := inputFiring(fmt.Sprintf("doc_%d.js", i), []int{0, i})
			<-start
			rep, err := s.Eval(ctx, set, in)
			errs[i] = err
			if err == nil {
				got[i] = fingerprintSet(rep.Findings)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	for i := range n {
		require.NoError(t, errs[i], "goroutine %d", i)
		// Rule 0 fires for everyone; rule i fires only for document i. Worker 0
		// sees one finding because both indices are the same rule.
		want := 2
		if i == 0 {
			want = 1
		}
		require.Len(t, got[i], want, "goroutine %d saw the wrong finding set", i)
	}
	require.Equal(t, int64(1), s.Compiles())
}

func TestEvictDropsEverything(t *testing.T) {
	var s Session
	ctx := context.Background()
	modules := preparedFixture(120)

	_, err := s.Prepare(ctx, modules, nil)
	require.NoError(t, err)
	require.Equal(t, 1, s.CachedSets())

	s.Evict()
	require.Equal(t, 0, s.CachedSets())

	_, err = s.Prepare(ctx, modules, nil)
	require.NoError(t, err)
	require.Equal(t, int64(2), s.Compiles(), "after eviction the set compiles again")
}

func TestEvalRejectsNilSet(t *testing.T) {
	var s Session
	_, err := s.Eval(context.Background(), nil, inputFiring("x.js", nil))
	require.Error(t, err)
}

func TestPrepareSurfacesCompileErrors(t *testing.T) {
	var s Session
	_, err := s.Prepare(context.Background(), map[string]string{
		"rules/broken.rego": "package vulnetix.rules.broken\nthis is not rego",
	}, nil)
	require.Error(t, err, "a malformed rule must fail loudly, not produce an empty rule set")
}

func TestModulesDigestIsContentAddressed(t *testing.T) {
	a := map[string]string{"x.rego": "package a", "y.rego": "package b"}
	b := map[string]string{"y.rego": "package b", "x.rego": "package a"}
	require.Equal(t, ModulesDigest(a), ModulesDigest(b), "map order must not affect the digest")

	c := map[string]string{"x.rego": "package a", "y.rego": "package c"}
	require.NotEqual(t, ModulesDigest(a), ModulesDigest(c), "changed content must change the digest")

	// A rename with identical content is a different set: module names are part
	// of the compiled program.
	d := map[string]string{"x.rego": "package a", "z.rego": "package b"}
	require.NotEqual(t, ModulesDigest(a), ModulesDigest(d))

	require.NotEmpty(t, ModulesDigest(nil))
}

func TestNormaliseKinds(t *testing.T) {
	require.Equal(t, "", normaliseKinds(nil))
	require.Equal(t, "", normaliseKinds([]string{}))
	require.Equal(t, "iac,oci,sast", normaliseKinds([]string{"sast", "oci", "iac"}))
}

// TestSessionOnTheRealCorpus runs the actual embedded rules through the warm
// path, kind-split the way the language server will use it. Synthetic fixtures
// prove the caching logic; this proves it works against the real thing.
func TestSessionOnTheRealCorpus(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles the embedded corpus; skipped under -short")
	}
	modules, err := LoadAllModules(DefaultRulesFS, false, nil, "", io.Discard)
	require.NoError(t, err)

	var s Session
	ctx := context.Background()

	interactive, err := s.Prepare(ctx, modules, InteractiveKinds)
	require.NoError(t, err)
	full, err := s.Prepare(ctx, modules, nil)
	require.NoError(t, err)

	t.Logf("interactive set: %d rule modules; full set: %d", interactive.RuleCount, full.RuleCount)
	require.Less(t, interactive.RuleCount, full.RuleCount,
		"the keystroke set must be smaller than the full one, or the split buys nothing")

	// The whole reason for the split: secrets are most of the corpus.
	require.Less(t, float64(interactive.RuleCount)/float64(full.RuleCount), 0.5)

	// And both evaluate.
	in := &ScanInput{
		FileSet:        map[string]bool{"main.go": true, "go.mod": true},
		DirsByLanguage: map[string][]string{"go": {"."}},
		FileContents: map[string]string{
			"go.mod":  "module example.com/x\n\ngo 1.25\n",
			"main.go": "package main\n\nimport \"os/exec\"\n\nfunc run(h string) { exec.Command(\"sh\", \"-c\", \"ping \"+h) }\n",
		},
		ScanRoot: "/fixture",
	}
	for _, set := range []*PreparedSet{interactive, full} {
		rep, err := s.Eval(ctx, set, in)
		require.NoError(t, err)
		require.NotNil(t, rep)
	}
	require.Equal(t, int64(2), s.Compiles(), "two distinct kind filters, two compiles, no more")
}
