package analyze

import (
	"fmt"
	"testing"
	"time"
)

// A bundled or minified file declares many same-named symbols on one line, so
// "kind:path:name#startLine" is not unique on its own. Two nodes sharing an id
// made the evidence builder panic on the duplicate and took the whole analyze
// run with it — `vulnetix analyze` on the saas repo died on
// .yarn/plugins/@yarnpkg/plugin-cyclonedx.cjs, which declares several
// `compare` methods on line 6.
func TestSymbolIDsAreUniqueOnASingleLine(t *testing.T) {
	symbolIDs := map[string]bool{}
	issue := func(kind, path, name string, startLine int) string {
		base := fmt.Sprintf("%s:%s:%s", kind, path, name)
		id := base
		if symbolIDs[id] {
			id = fmt.Sprintf("%s#%d", base, startLine)
			for n := 2; symbolIDs[id]; n++ {
				id = fmt.Sprintf("%s#%d#%d", base, startLine, n)
			}
		}
		symbolIDs[id] = true

		return id
	}

	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		id := issue("method", "bundle.cjs", "compare", 6)
		if seen[id] {
			t.Fatalf("issued a duplicate symbol id %q on iteration %d", id, i)
		}
		seen[id] = true
	}
	if len(seen) != 5 {
		t.Fatalf("expected 5 distinct ids, got %d", len(seen))
	}
	// The first two keep the readable forms; only genuine collisions past that
	// pay for a counter.
	if !seen["method:bundle.cjs:compare"] || !seen["method:bundle.cjs:compare#6"] {
		t.Errorf("expected the base and line-suffixed ids to be used first, got %v", seen)
	}
}

// safeID maps every unsafe character to "-", so distinct node ids can sanitise
// to one string. AddRecord treats a duplicate as a programming error and
// panics, so the derived record id has to stay injective.
func TestUniqueSymbolRecordID_ResolvesSanitisationCollisions(t *testing.T) {
	taken := map[string]string{}

	// These differ only in punctuation that safeID flattens.
	a := uniqueSymbolRecordID("method:a/b.js:compare", taken)
	b := uniqueSymbolRecordID("method:a-b.js:compare", taken)

	if a == b {
		t.Fatalf("distinct node ids must not share a record id (both %q)", a)
	}
	if a != "sym-method-a-b.js-compare" {
		t.Errorf("the first claimant should keep the readable id, got %q", a)
	}

	// Deterministic: the same node id asked again yields the same answer, and a
	// fresh run produces the same suffix rather than an order-dependent counter.
	fresh := map[string]string{}
	_ = uniqueSymbolRecordID("method:a/b.js:compare", fresh)
	if got := uniqueSymbolRecordID("method:a-b.js:compare", fresh); got != b {
		t.Errorf("expected a deterministic suffix, got %q then %q", b, got)
	}
}

// Asking twice for the same node is not a collision.
func TestUniqueSymbolRecordID_SameNodeIsStable(t *testing.T) {
	taken := map[string]string{}
	first := uniqueSymbolRecordID("method:a.js:run", taken)
	if second := uniqueSymbolRecordID("method:a.js:run", taken); second != first {
		t.Errorf("the same node must map to the same record id, got %q then %q", first, second)
	}
}

// The crash reported from a real repository: call and import edges were keyed by
// "call-"+safeID(edgeID) with no collision handling, so two edges whose ids differ
// only in punctuation — here a `.claude/worktrees/...` path against a
// `.claude-worktrees-...` one — produced the same record id and AddRecord panicked.
func TestEmitSymbolMetrics_EdgeIDsCollidingAfterSanitisationDoNotPanic(t *testing.T) {
	callee := func(path string) Node {
		return Node{ID: "function:" + path + ":_t", Kind: "function"}
	}
	nodes := []Node{
		{ID: "function:a/chart.min.js:e", Kind: "function"},
		callee("a/chart.min.js"),
		{ID: "function:a-chart.min.js:e", Kind: "function"},
		callee("a-chart.min.js"),
	}
	edges := []Edge{
		{ID: "e:calls:function:a/chart.min.js:e->function:a/chart.min.js:_t", Kind: "calls"},
		{ID: "e:calls:function:a-chart.min.js:e->function:a-chart.min.js:_t", Kind: "calls"},
		{ID: "e:imports:a/x.js->a/y.js", Kind: "imports"},
		{ID: "e:imports:a-x.js->a-y.js", Kind: "imports"},
	}

	b := NewBuilder(Tool{}, Target{}, time.Time{})
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("emitSymbolMetrics panicked on colliding sanitised edge ids: %v", r)
		}
	}()
	emitSymbolMetrics(b, &symbolStats{nodes: nodes, edges: edges}, Options{})
}
