package sast

import (
	"context"
	"math/rand"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/require"
)

// The line builtins are defined by the Rego they replace. Each is evaluated
// beside that Rego over texts chosen to break a careless reimplementation
// (case folding beyond ASCII, invalid UTF-8, CRLF, empty and newline-only
// text, keywords of other types) and over random ones, and must give the same
// answer every time.
func TestLineBuiltinsMatchRego(t *testing.T) {
	const module = `package t

import rego.v1

rego_has(s, kws) if {
	low := lower(s)
	some k in kws
	contains(low, k)
}

has := vulnetix.contains_any_fold(input.text, input.kws)
want_has := rego_has(input.text, input.kws)

kw_lines := vulnetix.keyword_lines(input.text, input.kws)
want_kw_lines := {i: line | some i, line in split(input.text, "\n"); rego_has(line, input.kws)}

pat_lines := vulnetix.pattern_lines(input.text, input.pattern)
want_pat_lines := {i: line | some i, line in split(input.text, "\n"); regex.match(input.pattern, line)}

sub_lines := vulnetix.lines_containing(input.text, input.kws)
want_sub_lines := {i: line | some i, line in split(input.text, "\n"); some s in input.kws; contains(line, s)}
`
	q, err := rego.New(
		rego.Query("data.t"),
		rego.Module("t.rego", module),
	).PrepareForEval(context.Background())
	require.NoError(t, err)

	check := func(text string, kws []any, pattern string) {
		t.Helper()
		rs, err := q.Eval(context.Background(), rego.EvalInput(map[string]any{"text": text, "kws": kws, "pattern": pattern}))
		require.NoError(t, err)
		got := rs[0].Expressions[0].Value.(map[string]any)
		want := got["want_has"] == true
		require.Equal(t, want, got["has"], "contains_any_fold(%q, %v)", text, kws)
		require.Equal(t, got["want_kw_lines"], got["kw_lines"], "keyword_lines(%q, %v)", text, kws)
		require.Equal(t, got["want_pat_lines"], got["pat_lines"], "pattern_lines(%q, %q)", text, pattern)
		require.Equal(t, got["want_sub_lines"], got["sub_lines"], "lines_containing(%q, %v)", text, kws)
	}

	texts := []string{
		"",
		"\n",
		"\n\n",
		"no newline Secret",
		"TOKEN=abc\r\npassword: x\r\n",
		"first\nSECRET_KEY = \"x\"\n\nlast line\n",
		"İstanbul ΣΊΣΥΦΟΣ secret\nK (Kelvin sign) key\n",
		"bad \xff\xfe utf8 secret\n\xc3\x28 token\n",
		strings.Repeat("aws_secret_access_key=AKIA\n", 3000), // longer than lowerMemoMin
		strings.Repeat("x", lowerMemoMin+10) + "\nApiKey: 1\n",
	}
	kwSets := [][]any{
		{"secret"},
		{"token", "password"},
		{"api", "key", "secret"},
		{"i̇stanbul", "σίσυφος", "kelvin"},
		{"�"},
		{1, "secret", true},
		{},
		{"=="},
		{"Secret", "TOKEN", "\n"},
		{""},
	}
	patterns := []string{`(?i)secret`, `^\s*$`, `[A-Z]{4}`, `token|password`, `\x{FFFD}`}
	for _, text := range texts {
		for _, kws := range kwSets {
			for _, p := range patterns {
				check(text, kws, p)
			}
		}
	}

	rng := rand.New(rand.NewSource(1))
	alphabet := []string{"a", "B", "k", "E", "y", "\n", "\r", " ", "=", "S", "e", "c", "R", "t", "É", "é", "ß", "\xff", "İ"}
	for range 300 {
		var b strings.Builder
		for range rng.Intn(80) {
			b.WriteString(alphabet[rng.Intn(len(alphabet))])
		}
		check(b.String(), []any{"key", "sec", "é", "ss"}, `(?i)ke?y|s+e`)
	}
}

// One evaluation lowers a long text once, however many rules ask, and never
// serves one string's lower case for another that happens to share its length.
func TestLowerOfMemoIsPerString(t *testing.T) {
	bctx := rego.BuiltinContext{Cache: map[any]any{}}
	a := strings.Repeat("ABC", lowerMemoMin)
	b := strings.Repeat("XYZ", lowerMemoMin)
	require.Equal(t, strings.ToLower(a), lowerOf(bctx, a))
	require.Equal(t, strings.ToLower(b), lowerOf(bctx, b))
	require.Equal(t, strings.ToLower(a), lowerOf(bctx, a))
	require.Len(t, bctx.Cache, 2)
	require.Equal(t, "short", lowerOf(bctx, "SHORT"))
	require.Len(t, bctx.Cache, 2, "a short string is not memoised")
}
