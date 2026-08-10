package sast

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/open-policy-agent/opa/v1/rego"
	"golang.org/x/sync/singleflight"
)

// Session holds compiled, prepared rule sets across evaluations.
//
// Engine.Evaluate compiles fresh on every call: evalModules calls
// compileModules per shard, per invocation, so Engine.compileOnce is dead on
// the sharded path. For a process that runs once and exits that is fine. For
// the language server, which evaluates on every keystroke, it is the difference
// between usable and not.
//
// Two changes carry it, and both were measured before being built (see
// session_bench_test.go):
//
//   - Cache the compiled shards, keyed by CompileKey. Compiling all 1,899
//     embedded modules costs 1.72s in one compiler, 0.30s across 16 shards.
//     Note that this is roughly 50x cheaper than the ~85s the comment at the
//     top of engine.go claims; that comment is stale.
//   - Prepare each shard's query once with rego.PrepareForEval rather than
//     building a fresh rego.New(...).Eval per call. Preparation costs 7.5ms and
//     a prepared query is safe to Eval concurrently from many goroutines
//     against different inputs, which TestPreparedQueryConcurrentEvalParity
//     proves under -race.
//
// The larger lever is not caching at all, it is what you choose to evaluate.
// Warm evaluation costs ~59ms per file across the whole corpus, and 92% of that
// is the 1,092 secrets rules, which declare no languages and so survive every
// language filter while each iterating every file. Against sast+iac+oci alone a
// single file costs 10.4ms rather than 231ms. Callers express that with Kinds;
// the language server passes InteractiveKinds on keystroke and all kinds on
// save.
//
// A Session is safe for concurrent use. The zero value is ready.
type Session struct {
	mu    sync.RWMutex
	sets  map[CompileKey]*PreparedSet
	group singleflight.Group

	// compiles counts calls that actually compiled, as opposed to being served
	// from cache. Instrumentation for TestWarmCacheHit; a cache that silently
	// stopped hitting would otherwise look identical to one that works.
	compiles atomic.Int64
}

// CompileKey identifies a compiled rule set. Any change to it is a different
// entry, which is what makes invalidation a lookup rather than a signal:
// changing --rule packs, toggling default rules or narrowing kinds all produce
// a different key, so the old entry is simply not found.
type CompileKey struct {
	// ModulesDigest is a content hash over the module set, so an edited rule
	// pack on disk produces a different key without anyone having to notice
	// that it changed.
	ModulesDigest string
	// ShardCount is part of the key because the shard split determines which
	// modules compile together.
	ShardCount int
	// Kinds is the sorted, comma-joined kind filter, or "" for no filter.
	Kinds string
}

func (k CompileKey) String() string {
	kinds := k.Kinds
	if kinds == "" {
		kinds = "all"
	}
	return fmt.Sprintf("%s/shards=%d/kinds=%s", k.ModulesDigest[:12], k.ShardCount, kinds)
}

// PreparedSet is a compiled and prepared rule set, ready to evaluate.
type PreparedSet struct {
	Key CompileKey

	// RuleCount is how many rule modules survived filtering. Reported so a
	// caller can tell "evaluated 140 rules" from "evaluated 1,232".
	RuleCount int

	queries []rego.PreparedEvalQuery
}

// Prepare compiles and prepares `modules`, restricted to `kinds`, or returns
// the cached result of having done so.
//
// kinds is a rule-kind filter; nil or empty means every kind. Shared library
// modules are always retained regardless of the filter, because OPA compiles
// every module together and dropping a dependency of a kept rule fails the
// whole evaluation.
//
// Concurrent callers asking for the same key block on the first rather than
// each compiling their own copy: on a cold start with several open documents
// that is the difference between one compile and one per document.
func (s *Session) Prepare(ctx context.Context, modules map[string]string, kinds []string) (*PreparedSet, error) {
	filtered := FilterModulesToKinds(modules, kinds)
	key := CompileKey{
		ModulesDigest: ModulesDigest(filtered),
		ShardCount:    shardCount(countRuleModules(filtered)),
		Kinds:         normaliseKinds(kinds),
	}

	if set := s.lookup(key); set != nil {
		return set, nil
	}

	// singleflight keyed on the same value as the cache, so the deduplication
	// and the cache agree on what "the same work" means.
	v, err, _ := s.group.Do(key.String(), func() (any, error) {
		// Re-check under the flight: a caller that queued behind the first one
		// should get its result, not compile again.
		if set := s.lookup(key); set != nil {
			return set, nil
		}
		set, err := s.build(ctx, key, filtered)
		if err != nil {
			return nil, err
		}
		s.store(key, set)
		return set, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*PreparedSet), nil
}

func (s *Session) lookup(key CompileKey) *PreparedSet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sets[key]
}

func (s *Session) store(key CompileKey, set *PreparedSet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sets == nil {
		s.sets = make(map[CompileKey]*PreparedSet, 4)
	}
	s.sets[key] = set
}

// build does the expensive work: partition, shard, compile, prepare.
func (s *Session) build(ctx context.Context, key CompileKey, modules map[string]string) (*PreparedSet, error) {
	s.compiles.Add(1)

	shared, rules := partitionModules(modules)
	set := &PreparedSet{Key: key, RuleCount: len(rules)}

	if key.ShardCount <= 1 {
		q, err := prepareModules(ctx, modules)
		if err != nil {
			return nil, err
		}
		set.queries = []rego.PreparedEvalQuery{q}
		return set, nil
	}

	shards := shardModules(rules, key.ShardCount)
	queries := make([]rego.PreparedEvalQuery, len(shards))
	errs := make([]error, len(shards))
	var wg sync.WaitGroup
	for i := range shards {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			mods := make(map[string]string, len(shared)+len(shards[i]))
			maps.Copy(mods, shared)
			maps.Copy(mods, shards[i])
			queries[i], errs[i] = prepareModules(ctx, mods)
		}(i)
	}
	wg.Wait()

	// A failure in any shard is fatal, matching Evaluate's all-or-nothing
	// behaviour: a partial rule set would silently under-report.
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}

	set.queries = queries
	return set, nil
}

// Eval runs a prepared set against an input and returns the union of findings.
//
// The input is not copied and is only read, so the same *ScanInput may be
// evaluated by several sessions or shards at once.
func (s *Session) Eval(ctx context.Context, set *PreparedSet, input *ScanInput) (*SASTReport, error) {
	if set == nil {
		return nil, fmt.Errorf("sast: Eval called with a nil PreparedSet")
	}

	reports := make([]*SASTReport, len(set.queries))
	errs := make([]error, len(set.queries))
	var wg sync.WaitGroup
	for i := range set.queries {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			reports[i], errs[i] = evalPrepared(ctx, set.queries[i], input)
		}(i)
	}
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}

	var allRules []RuleMetadata
	var allFindings []Finding
	for _, rep := range reports {
		if rep == nil {
			continue
		}
		allRules = append(allRules, rep.Rules...)
		allFindings = append(allFindings, rep.Findings...)
	}
	// Deterministic across shards and runs. Callers must not depend on order
	// anyway, but a stable one makes golden tests possible.
	sortFindings(allFindings)

	return &SASTReport{
		Findings:    allFindings,
		Rules:       allRules,
		RulesLoaded: len(allRules),
	}, nil
}

// Run prepares and evaluates in one call, which is what most callers want.
func (s *Session) Run(ctx context.Context, modules map[string]string, kinds []string, input *ScanInput) (*SASTReport, error) {
	set, err := s.Prepare(ctx, modules, kinds)
	if err != nil {
		return nil, err
	}
	return s.Eval(ctx, set, input)
}

// Compiles reports how many times this session actually compiled rather than
// serving a cached set. Test instrumentation.
func (s *Session) Compiles() int64 { return s.compiles.Load() }

// Evict drops every cached set. The language server calls this when the rule
// configuration changes in a way that is not captured by the digest, and when
// memory needs reclaiming.
func (s *Session) Evict() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sets = nil
}

// CachedSets reports how many distinct rule sets are held. Each one retains a
// compiled OPA program, so this is the number that matters for memory.
func (s *Session) CachedSets() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sets)
}

// prepareModules compiles a module set and prepares the standard query against
// it. Stateless, so shards prepare concurrently.
func prepareModules(ctx context.Context, modules map[string]string) (rego.PreparedEvalQuery, error) {
	compiler, err := compileModules(modules)
	if err != nil {
		return rego.PreparedEvalQuery{}, err
	}
	return rego.New(
		rego.Compiler(compiler),
		rego.Query("data.vulnetix.rules"),
	).PrepareForEval(ctx)
}

// evalPrepared evaluates one prepared query and extracts its findings.
func evalPrepared(ctx context.Context, q rego.PreparedEvalQuery, input *ScanInput) (*SASTReport, error) {
	rs, err := q.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("eval: %w", err)
	}
	rules, err := extractAllMetadata(rs)
	if err != nil {
		return nil, err
	}
	findings, err := extractAllFindings(rs, rules)
	if err != nil {
		return nil, err
	}
	return &SASTReport{Findings: findings, Rules: rules, RulesLoaded: len(rules)}, nil
}

// ModulesDigest is a content hash over a module set: sha256 over the sorted
// (name, sha256(source)) pairs.
//
// Hashing content rather than tracking mtimes means an externally cloned rule
// pack that changed on disk produces a different key without anything having to
// observe the change.
func ModulesDigest(modules map[string]string) string {
	names := make([]string, 0, len(modules))
	for name := range modules {
		names = append(names, name)
	}
	sort.Strings(names)

	h := sha256.New()
	for _, name := range names {
		inner := sha256.Sum256([]byte(modules[name]))
		h.Write([]byte(name))
		h.Write([]byte{0})
		h.Write(inner[:])
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// normaliseKinds sorts and joins a kind filter so that equivalent filters given
// in different orders produce the same cache key.
func normaliseKinds(kinds []string) string {
	if len(kinds) == 0 {
		return ""
	}
	out := make([]string, len(kinds))
	copy(out, kinds)
	sort.Strings(out)
	return strings.Join(out, ",")
}

func countRuleModules(modules map[string]string) int {
	n := 0
	for _, src := range modules {
		if strings.Contains(src, "package vulnetix.rules.") {
			n++
		}
	}
	return n
}
