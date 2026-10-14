package efficacy

import (
	"regexp/syntax"
	"slices"
	"strings"
	"unicode"
)

// Sample produces a string that matches pattern, built from the pattern's own
// syntax tree. It exists so a secret-detection rule can be proven to fire on
// the token shape it describes without a realistic credential ever being
// committed (provider push protection would rightly block that, and a test
// corpus of live-looking keys is its own leak).
//
// variant selects among alternatives and repetition lengths, so successive
// variants exercise different branches. Character runs are drawn without
// replacement from the class, which maximises entropy: an entropy-gated rule
// should accept a sample, and when it does not, the threshold is unreachable
// for that alphabet.
//
// The result is checked against the compiled pattern; an error means no
// variant up to the limit could satisfy the pattern's assertions (\b, ^, $).
func Sample(pattern string, variant int) (full, group string, err error) {
	return SampleMode(pattern, variant, modeHigh)
}

func parseSimplified(pattern string) (*syntax.Regexp, error) {
	tree, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, err
	}
	return tree.Simplify(), nil
}

type gen struct {
	seed uint64
	mode genMode
}

func (g *gen) next() uint64 {
	// xorshift64*: deterministic, no global state.
	g.seed ^= g.seed >> 12
	g.seed ^= g.seed << 25
	g.seed ^= g.seed >> 27
	return g.seed * 2685821657736338717
}

func (g *gen) intn(n int) int {
	if n <= 1 {
		return 0
	}
	return int(g.next() % uint64(n))
}

const repeatCap = 64

func (g *gen) emit(b *strings.Builder, re *syntax.Regexp) {
	switch re.Op {
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			b.WriteRune(r)
		}
	case syntax.OpCharClass:
		g.run(b, re.Rune, 1)
	case syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		g.run(b, []rune{'0', '9', 'A', 'Z', 'a', 'z'}, 1)
	case syntax.OpCapture:
		for _, s := range re.Sub {
			g.emit(b, s)
		}
	case syntax.OpConcat:
		for i := 0; i < len(re.Sub); i++ {
			s := re.Sub[i]
			// A run of one class (`[A-Za-z0-9]{40}`) is drawn as one sequence
			// so it has no repeated characters until the class is exhausted.
			if cls, n, ok := classRun(s); ok {
				g.run(b, cls, n(g))
				continue
			}
			g.emit(b, s)
		}
	case syntax.OpAlternate:
		g.emit(b, re.Sub[g.intn(len(re.Sub))])
	case syntax.OpQuest:
		if g.intn(3) != 0 {
			g.emit(b, re.Sub[0])
		}
	case syntax.OpStar, syntax.OpPlus, syntax.OpRepeat:
		if cls, n, ok := classRun(re); ok {
			g.run(b, cls, n(g))
			return
		}
		lo, hi := repeatBounds(re)
		n := lo
		if hi > lo {
			n = lo + g.intn(min(hi, lo+3)-lo+1)
		}
		for i := 0; i < n; i++ {
			g.emit(b, re.Sub[0])
		}
	default:
		// Empty match and assertions emit nothing; Sample verifies the result.
	}
}

func repeatBounds(re *syntax.Regexp) (lo, hi int) {
	switch re.Op {
	case syntax.OpStar:
		return 0, 1
	case syntax.OpPlus:
		return 1, 2
	case syntax.OpQuest:
		return 0, 1
	default:
		lo, hi = re.Min, re.Max
		if hi < 0 {
			hi = lo + 2
		}
		return lo, min(hi, max(lo, repeatCap))
	}
}

// classRun recognises a repetition of a single character class and returns
// the class and a length chooser.
func classRun(re *syntax.Regexp) ([]rune, func(*gen) int, bool) {
	switch re.Op {
	case syntax.OpStar, syntax.OpPlus, syntax.OpRepeat:
	default:
		return nil, nil, false
	}
	if len(re.Sub) != 1 {
		return nil, nil, false
	}
	sub := re.Sub[0]
	var cls []rune
	switch sub.Op {
	case syntax.OpCharClass:
		cls = sub.Rune
	case syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		cls = []rune{'0', '9', 'A', 'Z', 'a', 'z'}
	default:
		return nil, nil, false
	}
	lo, hi := repeatBounds(re)
	if re.Op == syntax.OpStar {
		lo, hi = 0, 0
	}
	// An unbounded token run (`{20,}`) is as long as real tokens are, not its
	// minimum: a JWT segment drawn at ten characters has a fraction of a real
	// one's entropy and would make every entropy gate look unreachable.
	if re.Op == syntax.OpRepeat && re.Max < 0 && lo >= 8 {
		span := 2*lo + 16
		return cls, func(g *gen) int { return lo + g.intn(span-lo+1) }, true
	}
	// `[A-Za-z0-9_-]+` over a token alphabet is a token body (each JWT segment
	// is one), not a one-character filler.
	if re.Op == syntax.OpPlus && len(expand(cls)) >= 16 {
		return cls, func(g *gen) int { return 16 + g.intn(49) }, true
	}
	return cls, func(g *gen) int {
		if hi > lo {
			return lo + g.intn(min(hi, lo+4)-lo+1)
		}
		return lo
	}, true
}

// run writes n characters from the class, preferring letters and digits, drawn
// without replacement until the pool is exhausted.
func (g *gen) run(b *strings.Builder, ranges []rune, n int) {
	if n <= 0 {
		return
	}
	pool := expand(ranges)
	if len(pool) == 0 {
		return
	}
	switch g.mode {
	case modeLowEntropy:
		for i := 0; i < n; i++ {
			b.WriteRune(pool[i%min(2, len(pool))])
		}
		return
	case modeRandom:
		for i := 0; i < n; i++ {
			b.WriteRune(pool[g.intn(len(pool))])
		}
		return
	case modePlaceholder:
		c := pool[0]
		for _, want := range "xXaA01zZ" {
			if slices.Contains(pool, want) {
				c = want
				break
			}
		}
		for i := 0; i < n; i++ {
			b.WriteRune(c)
		}
		return
	}
	order := make([]rune, len(pool))
	copy(order, pool)
	for written := 0; written < n; {
		// Fisher-Yates over the pool for each pass.
		for i := len(order) - 1; i > 0; i-- {
			j := g.intn(i + 1)
			order[i], order[j] = order[j], order[i]
		}
		for _, r := range order {
			if written == n {
				break
			}
			b.WriteRune(r)
			written++
		}
	}
}

// expand turns rune ranges into a pool, keeping printable ASCII and
// preferring alphanumerics when the class offers enough of them.
func expand(ranges []rune) []rune {
	var all, alnum []rune
	for i := 0; i+1 < len(ranges); i += 2 {
		lo, hi := ranges[i], ranges[i+1]
		if lo < 0x20 {
			lo = 0x20
		}
		if hi > 0x7e {
			hi = 0x7e
		}
		for r := lo; r <= hi; r++ {
			if !unicode.IsPrint(r) {
				continue
			}
			all = append(all, r)
			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				alnum = append(alnum, r)
			}
		}
	}
	if len(all) == 0 {
		// The class is outside printable ASCII (or only whitespace).
		for i := 0; i+1 < len(ranges); i += 2 {
			if ranges[i] <= ' ' && ranges[i+1] >= ' ' {
				return []rune{' '}
			}
		}
		if len(ranges) > 0 {
			return []rune{ranges[0]}
		}
		return nil
	}
	if len(alnum) >= 8 {
		return alnum
	}
	return all
}
