package regexlit

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/require"
)

// The ASCII letters a case-insensitive literal may hold are exactly those
// whose case-fold orbit stays in ASCII; k and s are the two that leave it.
func TestFoldExclusionsAreTheNonASCIIOrbits(t *testing.T) {
	var leaves []rune
	for r := 'a'; r <= 'z'; r++ {
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f >= 0x80 {
				leaves = append(leaves, r)
				break
			}
		}
	}
	require.Equal(t, []rune{'k', 's'}, leaves)
}

func TestFilterLiterals(t *testing.T) {
	cases := map[string][]string{
		`(?m)^\s*(?:from|import)\s+openai\b`:        {"openai"},
		`\b(?:OpenAI|AzureOpenAI|AsyncOpenAI)\s*\(`: {"OpenAI", "zureOpenAI", "syncOpenAI"}, // the parser factors out the shared "A"
		`(?i)anthropic`:   {"anthropic"},
		`(?i)openai`:      {"openai"},
		`(?i)keras`:       nil, // k and s fold outside ASCII
		`foo|ba`:          nil, // an alternative too short to test
		`x*openai`:        {"openai"},
		`(openai)?client`: {"client"},
		`a.b`:             nil,
		`(?:gpt){2,}`:     {"gpt"},
		`(?:gpt){0,3}`:    nil,
	}
	for expr, want := range cases {
		f := For(regexp.MustCompile(expr))
		var got []string
		for _, l := range f.lits {
			got = append(got, l.s)
		}
		require.ElementsMatch(t, want, got, expr)
	}
}

// The property that makes the filter safe: whenever a pattern matches a text,
// the filter lets the text through. Texts are built from pieces of the
// patterns themselves, in mixed case, with non-ASCII letters that fold to
// ASCII ones, so matches are common.
func TestFilterNeverHidesAMatch(t *testing.T) {
	patterns := []string{
		`(?m)^\s*(?:from|import)\s+openai\b`,
		`\b(?:OpenAI|AzureOpenAI|AsyncOpenAI)\s*\(`,
		`(?i)openai|anthropic`,
		`(?i)\bmodel\s*=\s*["']([^"']+)["']`,
		`(?i)(?:sha|md)[-_]?(?:1|5|256)`,
		`(?i)keras|tensorflow`,
		`(?:gpt){2,}x`,
		`(?i)aes[-_]?(?:128|256)[-_]?(?:gcm|cbc)`,
		`(?i)rsa`,
	}
	pieces := []string{
		"openai", "OpenAI", "OPENAI", "anthropic", "ANTHROPIC", "import ", "from ", "model", "= ", `"`, "'",
		"gpt", "x", "sha", "SHA", "-", "_", "256", "md", "5", "aes", "AES", "gcm", "CBC", "rsa", "RSA",
		"ke", "K", "K", "eras", "ſ", "tensorflow", " ", "\n", "(", "é", "İ", "\xff", "AzureOpenAI", "Async",
	}
	rng := rand.New(rand.NewSource(7))
	var res []*regexp.Regexp
	for _, p := range patterns {
		res = append(res, regexp.MustCompile(p))
	}
	matched := 0
	for range 20000 {
		var b strings.Builder
		for range rng.Intn(12) {
			b.WriteString(pieces[rng.Intn(len(pieces))])
		}
		s := b.String()
		text := NewText(s)
		for _, re := range res {
			if re.MatchString(s) {
				matched++
				require.True(t, For(re).MayMatch(text), "%q matches %q but was filtered out", re, s)
			}
		}
	}
	require.Greater(t, matched, 1000, "the texts must exercise matches")
}
