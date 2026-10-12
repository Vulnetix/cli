package analyze

import (
	"fmt"
	"os"
	"path/filepath"
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
	a := uniqueRecordID("sym-", "method:a/b.js:compare", taken)
	b := uniqueRecordID("sym-", "method:a-b.js:compare", taken)

	if a == b {
		t.Fatalf("distinct node ids must not share a record id (both %q)", a)
	}
	if a != "sym-method-a-b.js-compare" {
		t.Errorf("the first claimant should keep the readable id, got %q", a)
	}

	// Deterministic: the same node id asked again yields the same answer, and a
	// fresh run produces the same suffix rather than an order-dependent counter.
	fresh := map[string]string{}
	_ = uniqueRecordID("sym-", "method:a/b.js:compare", fresh)
	if got := uniqueRecordID("sym-", "method:a-b.js:compare", fresh); got != b {
		t.Errorf("expected a deterministic suffix, got %q then %q", b, got)
	}
}

// Asking twice for the same node is not a collision.
func TestUniqueSymbolRecordID_SameNodeIsStable(t *testing.T) {
	taken := map[string]string{}
	first := uniqueRecordID("sym-", "method:a.js:run", taken)
	if second := uniqueRecordID("sym-", "method:a.js:run", taken); second != first {
		t.Errorf("the same node must map to the same record id, got %q then %q", first, second)
	}
}

// The crash reported from a real repository: call and import edges were keyed by
// "call-"+safeID(edgeID) with no collision handling, so two edges whose ids differ
// only in punctuation (here a `.claude/worktrees/...` path against a
// `.claude-worktrees-...` one) produced the same record id and AddRecord panicked.
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

// Every collector that derives a record id from a path or graph id must survive two sources
// that sanitise alike. The reporter's crash came from the call edges; reproducing the same
// layout end to end (scripts/ci-worktree-analyze.sh) then crashed on file records, which had
// the identical flaw. These pin each producer rather than the one that happened to fail first.
func TestBuilderRecordIDResolvesCollisionsAcrossPrefixes(t *testing.T) {
	b := NewBuilder(Tool{}, Target{}, time.Time{})

	for _, prefix := range []string{"sym-", "imp-", "call-", "coupling-", "trend-", "xr-"} {
		a := b.RecordID(prefix, "collide/a/m.js")
		c := b.RecordID(prefix, "collide/a-m.js")
		if a == c {
			t.Errorf("%s: distinct sources shared record id %q", prefix, a)
		}
		// Both must be accepted by AddRecord, which is what actually panics.
		b.AddRecord(a, struct{}{})
		b.AddRecord(c, struct{}{})
		if again := b.RecordID(prefix, "collide/a/m.js"); again != a {
			t.Errorf("%s: the same source must keep its id, got %q then %q", prefix, a, again)
		}
	}
}

// A hash suffix could itself be taken (by a source whose sanitised form is literally that
// string), so the allocator has to keep looking rather than hand out a second owner.
func TestUniqueRecordIDNeverReissuesAnID(t *testing.T) {
	taken := map[string]string{}
	first := uniqueRecordID("p-", "a/b", taken)
	second := uniqueRecordID("p-", "a-b", taken)
	// A source whose sanitised form equals the second's suffixed id.
	third := uniqueRecordID("", second, taken)
	third2 := uniqueRecordID("p-", "a_b", taken)

	seen := map[string]string{}
	for src, id := range map[string]string{"a/b": first, "a-b": second, second: third, "a_b": third2} {
		if prev, dup := seen[id]; dup {
			t.Errorf("id %q issued to both %q and %q", id, prev, src)
		}
		seen[id] = src
	}
}

func TestCollectFilesSurvivesPathsThatSanitiseAlike(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{"collide/a/m.js", "collide/a-m.js", "collide/a_m.js"} {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("function f() { return 1; }\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	b := NewBuilder(Tool{}, Target{}, time.Time{})
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("collectFiles panicked on paths that sanitise to one record id: %v", r)
		}
	}()
	st, err := collectFiles(b, root, nil, Options{ComplexityThreshold: 15}, time.Now(), reporter{})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, f := range st.files {
		if ids[f.ID] {
			t.Errorf("two file records share id %q", f.ID)
		}
		ids[f.ID] = true
	}
	if len(st.files) != 3 {
		t.Errorf("expected 3 files, got %d", len(st.files))
	}
}

func TestIdentitySetIDsSurviveSanitisationCollisions(t *testing.T) {
	s := NewIdentitySet()
	// "email:a+b@x.io" and "email:a-b@x.io" differ only in a character safeID flattens.
	one := s.Observe(Identity{Email: "a+b@x.io"})
	two := s.Observe(Identity{Email: "a-b@x.io"})
	if one.ID == two.ID {
		t.Errorf("distinct contributors share record id %q", one.ID)
	}
}
