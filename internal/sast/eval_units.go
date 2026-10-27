package sast

import (
	"context"
	"fmt"
	"maps"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/open-policy-agent/opa/v1/rego"
)

// batchBytes is how much file text one evaluation of a per-file unit reads.
// Smaller batches spread a large group over more workers and keep OPA's
// per-evaluation memo small; each evaluation also pays a fixed cost for the
// unit's rule tree, which larger batches amortise. At 2 MiB one batch of a
// 74-rule group took 9 of a 13 second run on vdb-manager.
// The parity tests shrink it and turn batching off.
var (
	batchBytes      = 256 << 10
	perFileBatching = true
)

// evalUnit is one compiled module set and the batches of files it is
// evaluated against. A whole-scope unit has one batch holding every file in
// its scope; a per-file unit has as many as its scope needs.
type evalUnit struct {
	mods    map[string]string
	batches [][]string

	once  sync.Once
	query rego.PreparedEvalQuery
	err   error
	left  atomic.Int32 // batches not yet evaluated; the query is dropped at 0

	metaOnce sync.Once
	meta     []RuleMetadata
}

// prepare compiles the unit once, whichever worker gets to it first.
func (u *evalUnit) prepare(ctx context.Context) (rego.PreparedEvalQuery, error) {
	u.once.Do(func() {
		u.query, u.err = prepareModules(ctx, u.mods)
	})
	return u.query, u.err
}

// withShared is a rule subset plus the shared modules it compiles with. The
// in-method data-flow helpers are left out unless a rule calls them: they are
// a large part of the compile cost and few rules need them.
func withShared(shared, rules map[string]string) map[string]string {
	mods := make(map[string]string, len(shared)+len(rules))
	needsFlow := shardUsesFlow(rules)
	for name, src := range shared {
		if isFlowModule(src) && !needsFlow {
			continue
		}
		mods[name] = src
	}
	maps.Copy(mods, rules)
	return mods
}

// inputPaths is every file_contents key of in, sorted.
func inputPaths(in *ScanInput) []string {
	paths := make([]string, 0, len(in.FileContents))
	for p := range in.FileContents {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

// fileBatches splits in's files, in path order, into batches of about max
// bytes. A file larger than max is a batch of its own. A scope with no files
// is one empty batch, so its rules are still evaluated once and report their
// metadata.
func fileBatches(in *ScanInput, max int) [][]string {
	var batches [][]string
	var cur []string
	size := 0
	for _, p := range inputPaths(in) {
		n := len(in.FileContents[p])
		if len(cur) > 0 && size+n > max {
			batches = append(batches, cur)
			cur, size = nil, 0
		}
		cur = append(cur, p)
		size += n
	}
	if len(cur) > 0 || len(batches) == 0 {
		batches = append(batches, cur)
	}
	return batches
}

// evalWorkers is how many evaluations run at once: the cores, up to the shard
// ceiling. VULNETIX_SAST_WORKERS overrides it.
func evalWorkers() int {
	if v := strings.TrimSpace(os.Getenv("VULNETIX_SAST_WORKERS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			return n
		}
	}
	return max(1, min(runtime.GOMAXPROCS(0), shardMaxCount))
}

type unitTask struct {
	unit  *evalUnit
	batch []string
}

// runUnits evaluates every batch of every unit on a pool of workers and
// returns one report per unit. A unit's rule metadata is read from its first
// evaluation only. Any compile or evaluation error fails the whole run, as a
// partial rule set would under-report without saying so.
func runUnits(units []*evalUnit, terms *regoInput, workers int) ([]*SASTReport, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Costliest unit first, a unit's batches together. A batch costs roughly
	// its rules times its bytes; starting the big units early keeps any of
	// them from being the tail of the run while the other workers sit idle.
	// Keeping a unit's batches together means only about one compiled unit
	// per worker is alive at a time: interleaving every batch by cost was
	// half a second faster on vdb-manager and held three times the memory.
	type plan struct {
		unit  *evalUnit
		cost  int
		tasks []unitTask
	}
	plans := make([]plan, 0, len(units))
	for _, u := range units {
		u.left.Store(int32(len(u.batches)))
		rules := 0
		for _, src := range u.mods {
			if strings.Contains(src, "package vulnetix.rules.") {
				rules++
			}
		}
		p := plan{unit: u}
		for _, b := range u.batches {
			c := rules * (terms.size(b) + 4096)
			p.cost += c
			p.tasks = append(p.tasks, unitTask{unit: u, batch: b})
		}
		plans = append(plans, p)
	}
	sort.SliceStable(plans, func(i, j int) bool { return plans[i].cost > plans[j].cost })
	var tasks []unitTask
	for _, p := range plans {
		tasks = append(tasks, p.tasks...)
	}

	findings := make([][]Finding, len(tasks))
	next := atomic.Int64{}
	var firstErr error
	var errOnce sync.Once
	var wg sync.WaitGroup
	for range max(1, min(workers, len(tasks))) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= len(tasks) || ctx.Err() != nil {
					return
				}
				t := tasks[i]
				fs, err := t.run(ctx, terms)
				if err != nil {
					errOnce.Do(func() { firstErr = err; cancel() })
					return
				}
				findings[i] = fs
			}
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}

	byUnit := make(map[*evalUnit]*SASTReport, len(units))
	for i, t := range tasks {
		rep := byUnit[t.unit]
		if rep == nil {
			rep = &SASTReport{Rules: t.unit.meta, RulesLoaded: len(t.unit.meta)}
			byUnit[t.unit] = rep
		}
		rep.Findings = append(rep.Findings, findings[i]...)
	}
	out := make([]*SASTReport, 0, len(units))
	for _, u := range units {
		if rep := byUnit[u]; rep != nil {
			out = append(out, rep)
		}
	}
	return out, nil
}

func (t unitTask) run(ctx context.Context, terms *regoInput) ([]Finding, error) {
	u := t.unit
	q, err := u.prepare(ctx)
	if err != nil {
		return nil, err
	}
	rs, err := q.Eval(ctx, rego.EvalParsedInput(terms.valueOf(t.batch)))
	if err != nil {
		return nil, fmt.Errorf("eval: %w", err)
	}
	var metaErr error
	u.metaOnce.Do(func() { u.meta, metaErr = extractAllMetadata(rs) })
	if metaErr != nil {
		return nil, metaErr
	}
	fs, err := extractAllFindings(rs, u.meta)
	if err != nil {
		return nil, err
	}
	if u.left.Add(-1) == 0 {
		// Every batch is done: let the compiled unit go.
		u.query = rego.PreparedEvalQuery{}
		u.mods = nil
	}
	return fs, nil
}
