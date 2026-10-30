package versions

import (
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"testing/quick"
)

// versionString generates a Version randomly, then returns both the Version and
// a string that Parse accepts. This avoids trying to parse arbitrary byte
// garbage and instead exercises the shapes the parser actually supports.
type versionString struct {
	s   string
	v   Version
	err error
}

var _ quick.Generator = (*versionString)(nil)

// Generate implements quick.Generator.
func (versionString) Generate(rand *rand.Rand, size int) reflect.Value {
	gs := newGenState(rand, size)
	s := gs.version()
	v, err := Parse(s)
	return reflect.ValueOf(versionString{s: s, v: v, err: err})
}

// genState builds parseable version strings from a small grammar.
type genState struct {
	r    *rand.Rand
	size int
}

func newGenState(r *rand.Rand, size int) genState {
	if size < 0 {
		size = -size
	}
	if size > 6 {
		size = 6
	}
	return genState{r: r, size: size}
}

func (g genState) bool() bool { return g.r.Intn(2) == 0 }

func (g genState) pick(opts ...string) string {
	return opts[g.r.Intn(len(opts))]
}

func (g genState) segmentCount() int {
	// Between 1 and 2+size segments; size is capped at 6 in newGenState.
	return 1 + g.r.Intn(2+g.size)
}

func (g genState) segmentWildcard() string {
	return g.pick("x", "X", "*")
}

func (g genState) numericIdent() string {
	// Keep numeric identifiers small enough to fit in uint64 reliably.
	return fmt.Sprintf("%d", g.r.Intn(1000))
}

func (g genState) alphaIdent() string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	n := 1 + g.r.Intn(4)
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[g.r.Intn(len(letters))]
	}
	return string(b)
}

func (g genState) prereleaseIdent() string {
	switch g.r.Intn(3) {
	case 0:
		return g.numericIdent()
	case 1:
		return g.alphaIdent()
	default:
		return g.alphaIdent() + g.numericIdent()
	}
}

func (g genState) prerelease() string {
	n := 1 + g.r.Intn(1+g.size)
	parts := make([]string, n)
	for i := range parts {
		parts[i] = g.prereleaseIdent()
	}
	return strings.Join(parts, ".")
}

func (g genState) build() string {
	parts := make([]string, 1+g.r.Intn(2))
	for i := range parts {
		parts[i] = g.alphaIdent()
	}
	return strings.Join(parts, ".")
}

func (g genState) version() string {
	// Occasionally generate the all-wildcard version.
	if g.r.Intn(20) == 0 {
		return g.segmentWildcard()
	}

	parts := make([]string, g.segmentCount())
	hasWildcard := false
	for i := range parts {
		if !hasWildcard && g.r.Intn(6) == 0 {
			parts[i] = g.segmentWildcard()
			hasWildcard = true
			continue
		}
		parts[i] = g.numericIdent()
	}
	s := strings.Join(parts, ".")

	// Parse strips a v prefix only ahead of a number, so "v*.1" is not a
	// version; prefix only when the first segment is numeric.
	if g.bool() && !hasWildcardPrefix(s) {
		s = g.pick("", "v", "V") + s
	}

	if g.r.Intn(10) == 0 {
		// Go-style pseudo-version: 0.0.0-20220622213112-05595931fe9d or
		// 5.3.2-0.20260526213025-e8e5b83ca9a5.
		base := strings.TrimPrefix(s, "v")
		base = strings.TrimPrefix(base, "V")
		if strings.Contains(base, "*") || strings.Contains(base, "x") ||
			strings.Contains(base, "X") {
			return base
		}
		seg := strings.Split(base, ".")
		if len(seg) >= 3 {
			// Force a parseable pseudo suffix only when the core is usable.
			timestamp := fmt.Sprintf("%014d", g.r.Intn(100000000000000))
			hash := fmt.Sprintf("%07x", g.r.Intn(0x10000000))
			if g.bool() {
				s = fmt.Sprintf("%s.%s.%s-0.%s-%s", seg[0], seg[1], seg[2], timestamp, hash)
			} else {
				s = fmt.Sprintf("%s.%s.%s-%s-%s", seg[0], seg[1], seg[2], timestamp, hash)
			}
		}
	} else if g.r.Intn(4) == 0 {
		s += "-" + g.prerelease()
	}

	if g.r.Intn(4) == 0 {
		s += "+" + g.build()
	}

	// PEP 440 cases are too specialized; keep the generator in SemVer land.
	return s
}

func hasWildcardPrefix(s string) bool {
	return strings.HasPrefix(s, "x") || strings.HasPrefix(s, "X") || strings.HasPrefix(s, "*")
}

// rangeString generates strings that might be range expressions; most are valid
// but we deliberately allow arbitrary text to exercise parser robustness.
type rangeString struct{ s string }

var _ quick.Generator = (*rangeString)(nil)

func (rangeString) Generate(rand *rand.Rand, size int) reflect.Value {
	gs := newGenState(rand, size)
	// 70% valid-looking range fragments, 30% arbitrary junk.
	var s string
	switch rand.Intn(10) {
	case 0, 1:
		s = gs.junk()
	case 2, 3:
		s = gs.pick(">= ", "<= ", "> ", "< ", "= ", "!= ") + gs.version()
	case 4:
		s = "[" + gs.version() + ", " + gs.version() + ")"
	case 5:
		s = "(" + gs.version() + ", " + gs.version() + "]"
	default:
		pieces := make([]string, 1+rand.Intn(2))
		for i := range pieces {
			if rand.Intn(2) == 0 {
				pieces[i] = gs.version()
			} else {
				pieces[i] = gs.pick(">=", "<=", ">", "<", "=", "!=") + " " + gs.version()
			}
		}
		s = strings.Join(pieces, " || ")
	}
	return reflect.ValueOf(rangeString{s: s})
}

func (g genState) junk() string {
	return g.pick(
		"", "unspecified", "n/a", "before 8.5.3", "8.x before 8.5.3",
		string([]rune{g.rune()}),
	)
}

func (g genState) rune() rune {
	// Index runes, not bytes: ≥, ≤ and ≠ are multi-byte, and a byte index
	// would only ever yield fragments of them.
	pool := []rune("<>≥≤≠=!.xX*@#$%^&")
	return pool[g.r.Intn(len(pool))]
}

// Every property below skips inputs that fail to parse, so the generator must
// actually produce parseable versions or those properties pass vacuously.
func TestGeneratedVersionsParse(t *testing.T) {
	f := func(vs versionString) bool {
		if vs.err != nil {
			t.Logf("generated %q does not parse: %v", vs.s, vs.err)
			return false
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 2000}); err != nil {
		t.Errorf("generator produced an unparseable version: %v", err)
	}
}

func TestCompareAntisymmetric(t *testing.T) {
	f := func(a, b versionString) bool {
		if a.err != nil || b.err != nil {
			return true // only compare parseable versions
		}
		return sign(Compare(a.v, b.v)) == -sign(Compare(b.v, a.v))
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Errorf("Compare antisymmetry failed: %v", err)
	}
}

func TestCompareTransitive(t *testing.T) {
	f := func(a, b, c versionString) bool {
		if a.err != nil || b.err != nil || c.err != nil {
			return true
		}
		ab := Compare(a.v, b.v)
		bc := Compare(b.v, c.v)
		if ab < 0 && bc < 0 {
			return Compare(a.v, c.v) < 0
		}
		if ab > 0 && bc > 0 {
			return Compare(a.v, c.v) > 0
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 300}); err != nil {
		t.Errorf("Compare transitivity failed: %v", err)
	}
}

func TestParseNoPanic(t *testing.T) {
	mustNotPanic := func(s string) (ok bool) {
		defer func() {
			if r := recover(); r != nil {
				ok = false
			}
		}()
		_, _ = Parse(s)
		return true
	}
	f := func(s string) bool {
		return mustNotPanic(s)
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 1000}); err != nil {
		t.Errorf("Parse panicked on generated string: %v", err)
	}

	// Shapes that have tripped version parsers: advisory prose, Unicode
	// comparison operators, many segments, and a component past uint64.
	for _, s := range []string{
		"", "unspecified", "8.x before 8.5.3", "≥ 1.0.0", "≤ 1.0.0", "≠ 1.0.0",
		"1.2.3.4.5.6.7.8.9.10.11.12-rc.1.2.3.4+build.1.2.3",
		strings.Repeat("9", 30) + ".0.0",
	} {
		if !mustNotPanic(s) {
			t.Errorf("Parse(%q) panicked", s)
		}
	}
}

func TestParseRoundTrip(t *testing.T) {
	f := func(a versionString) bool {
		if a.err != nil {
			return true
		}
		v := a.v
		if v.Wildcard {
			return true
		}
		canonical := renderVersion(v)
		v2, err := Parse(canonical)
		if err != nil {
			return false
		}
		return Compare(v, v2) == 0
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Errorf("Parse round-trip failed: %v", err)
	}
}

func TestEqualExactSymmetric(t *testing.T) {
	f := func(a, b versionString) bool {
		if a.err != nil || b.err != nil {
			return true
		}
		for _, p := range []PseudoPolicy{PseudoBaseEqual, PseudoStrict} {
			gotAB := EqualExact(a.v, b.v, p)
			gotBA := EqualExact(b.v, a.v, p)
			if gotAB != gotBA {
				return false
			}
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Errorf("EqualExact symmetry failed: %v", err)
	}
}

func TestParseRangeNoPanic(t *testing.T) {
	mustNotPanic := func(s string) (ok bool) {
		defer func() {
			if r := recover(); r != nil {
				ok = false
			}
		}()
		_, _ = ParseRange(s)
		return true
	}

	f := func(rng rangeString) bool {
		return mustNotPanic(rng.s)
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Errorf("ParseRange panicked on generated range string: %v", err)
	}
}

func TestParseRangeContainsNoPanic(t *testing.T) {
	mustNotPanic := func(rng string, vs versionString) (ok bool) {
		defer func() {
			if r := recover(); r != nil {
				ok = false
			}
		}()
		rs, err := ParseRange(rng)
		if err != nil {
			return true
		}
		if vs.err != nil {
			return true
		}
		rs.Contains(vs.v, PseudoBaseEqual)
		rs.Contains(vs.v, PseudoStrict)
		return true
	}

	f := func(rng rangeString, vs versionString) bool {
		return mustNotPanic(rng.s, vs)
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Errorf("Contains panicked on generated inputs: %v", err)
	}
}

func TestParseRangeExactContainsVersion(t *testing.T) {
	f := func(vs versionString) bool {
		if vs.err != nil {
			return true
		}
		// Build a single exact constraint "= X" and check it contains X.
		expr := "= " + renderVersion(vs.v)
		rs, err := ParseRange(expr)
		if err != nil {
			// renderVersion output is always a valid version, so "= X" must
			// parse; skipping here would let the property pass vacuously.
			t.Logf("ParseRange(%q): %v", expr, err)
			return false
		}
		return rs.Contains(vs.v, PseudoBaseEqual)
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Errorf("Exact range did not contain its own version: %v", err)
	}
}

func sign(x int) int {
	switch {
	case x < 0:
		return -1
	case x > 0:
		return 1
	}
	return 0
}
