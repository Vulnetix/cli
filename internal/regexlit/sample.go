package regexlit

import (
	"math/rand"
	"regexp"
	"regexp/syntax"
	"strings"
)

// SampleTexts builds n texts likely to match re, for proving that re is
// filtered soundly: re's literal pieces, in mixed case and beside the
// non-ASCII runes that fold to k and s, joined with the separators patterns
// look for. A test runs re over each text and requires MayMatch wherever
// MatchString holds.
func SampleTexts(re *regexp.Regexp, n int, seed int64) []string {
	pieces := []string{" ", "  ", "\n", "\t", "(", ")", "'", `"`, "=", ":", ".", "/", "-", "_", ",", "K", "ſ", "é", "0", "1"}
	var own []string
	if tree, err := syntax.Parse(re.String(), syntax.Perl); err == nil {
		collect(tree, &own)
	}
	rng := rand.New(rand.NewSource(seed))
	out := make([]string, 0, n)
	for range n {
		var b strings.Builder
		for range 1 + rng.Intn(12) {
			p := pieces[rng.Intn(len(pieces))]
			if len(own) > 0 && rng.Intn(3) > 0 {
				p = own[rng.Intn(len(own))]
			}
			switch rng.Intn(4) {
			case 0:
				p = strings.ToUpper(p)
			case 1:
				p = strings.ToLower(p)
			}
			b.WriteString(p)
		}
		out = append(out, b.String())
	}
	return out
}

func collect(re *syntax.Regexp, pieces *[]string) {
	if re.Op == syntax.OpLiteral {
		*pieces = append(*pieces, string(re.Rune))
	}
	for _, sub := range re.Sub {
		collect(sub, pieces)
	}
}
