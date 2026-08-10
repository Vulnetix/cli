package rangefix

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// The table below is shared with the TypeScript implementation in the VS Code
// extension. Both must agree, because a range computed differently on each side
// puts the squiggle in one place and the lightbulb in another.
//
// Positions are UTF-16 code units, which is what makes the emoji and CJK cases
// load-bearing rather than decorative.

type tc struct {
	name       string
	doc        string
	startLine  int
	endLine    int
	opts       Options
	wantOK     bool
	wantStart  Position
	wantEnd    Position
	wantConf   Confidence
	wantSubstr string // the text the range covers, as a readability check
}

func TestColumns(t *testing.T) {
	cases := []tc{
		{
			name:       "snippet found on the line",
			doc:        "function f() {\n  return eval(expr);\n}\n",
			startLine:  2,
			opts:       Options{Kind: "sast", Snippet: "  return eval(expr);"},
			wantOK:     true,
			wantStart:  Position{Line: 1, Character: 2},
			wantEnd:    Position{Line: 1, Character: 20},
			wantConf:   ConfidenceExact,
			wantSubstr: "return eval(expr);",
		},
		{
			name:      "no snippet falls back to the trimmed line",
			doc:       "\t\tdangerous(x)\n",
			startLine: 1,
			opts:      Options{Kind: "sast"},
			wantOK:    true,
			wantStart: Position{Line: 0, Character: 2},
			wantEnd:   Position{Line: 0, Character: 14},
			wantConf:  ConfidenceLine,
		},
		{
			name:      "snippet that no longer matches falls back",
			doc:       "  somethingElse()\n",
			startLine: 1,
			opts:      Options{Kind: "sast", Snippet: "  return eval(expr);"},
			wantOK:    true,
			wantStart: Position{Line: 0, Character: 2},
			wantEnd:   Position{Line: 0, Character: 17},
			wantConf:  ConfidenceLine,
		},
		{
			name:      "leading whitespace excluded",
			doc:       "        indented()\n",
			startLine: 1,
			wantOK:    true,
			wantStart: Position{Line: 0, Character: 8},
			wantEnd:   Position{Line: 0, Character: 18},
			wantConf:  ConfidenceLine,
		},
		{
			name:      "trailing whitespace excluded",
			doc:       "code()      \n",
			startLine: 1,
			wantOK:    true,
			wantStart: Position{Line: 0, Character: 0},
			wantEnd:   Position{Line: 0, Character: 6},
			wantConf:  ConfidenceLine,
		},
		{
			name:      "tabs count as one unit each",
			doc:       "\t\t\tcode()\n",
			startLine: 1,
			wantOK:    true,
			wantStart: Position{Line: 0, Character: 3},
			wantEnd:   Position{Line: 0, Character: 9},
			wantConf:  ConfidenceLine,
		},
		{
			name:      "blank line gives a zero-width range",
			doc:       "\n",
			startLine: 1,
			wantOK:    true,
			wantStart: Position{Line: 0, Character: 0},
			wantEnd:   Position{Line: 0, Character: 0},
			wantConf:  ConfidenceLine,
		},
		{
			name:      "whitespace-only line gives a zero-width range",
			doc:       "      \n",
			startLine: 1,
			wantOK:    true,
			wantStart: Position{Line: 0, Character: 0},
			wantEnd:   Position{Line: 0, Character: 0},
			wantConf:  ConfidenceLine,
		},

		// ── Position encoding ────────────────────────────────────────────────
		// The reason this package exists in Go rather than being computed from
		// byte offsets on the wire.
		{
			name:       "emoji before the match count as two units each",
			doc:        "const x = '😀😀' + eval(y);\n",
			startLine:  1,
			opts:       Options{Kind: "sast", Snippet: "eval(y)"},
			wantOK:     true,
			wantStart:  Position{Line: 0, Character: 19},
			wantEnd:    Position{Line: 0, Character: 26},
			wantConf:   ConfidenceExact,
			wantSubstr: "eval(y)",
		},
		{
			name:       "CJK before the match count as one unit each",
			doc:        "const 说明 = eval(y);\n",
			startLine:  1,
			opts:       Options{Kind: "sast", Snippet: "eval(y)"},
			wantOK:     true,
			wantStart:  Position{Line: 0, Character: 11},
			wantEnd:    Position{Line: 0, Character: 18},
			wantConf:   ConfidenceExact,
			wantSubstr: "eval(y)",
		},
		{
			name:      "emoji-only indentation",
			doc:       "😀😀 code()\n",
			startLine: 1,
			wantOK:    true,
			wantStart: Position{Line: 0, Character: 0},
			wantEnd:   Position{Line: 0, Character: 11},
			wantConf:  ConfidenceLine,
		},

		// ── Multi-line ───────────────────────────────────────────────────────
		{
			name:      "multi-line snippet spans first to last",
			doc:       "a := query(\n  \"SELECT \" + name,\n)\n",
			startLine: 1,
			endLine:   3,
			opts:      Options{Kind: "sast", Snippet: "a := query(\n  \"SELECT \" + name,\n)"},
			wantOK:    true,
			wantStart: Position{Line: 0, Character: 0},
			wantEnd:   Position{Line: 2, Character: 1},
			wantConf:  ConfidenceSnippet,
		},
		{
			name:      "multi-line snippet whose last line is gone falls back",
			doc:       "a := query(\n  \"SELECT \" + name,\nSOMETHING ELSE\n",
			startLine: 1,
			endLine:   3,
			opts:      Options{Kind: "sast", Snippet: "a := query(\n)"},
			wantOK:    true,
			wantConf:  ConfidenceLine,
		},
		{
			name:      "endLine beyond the document is clamped",
			doc:       "one()\ntwo()\n",
			startLine: 1,
			endLine:   99,
			wantOK:    true,
			wantStart: Position{Line: 0, Character: 0},
			wantConf:  ConfidenceLine,
		},
		{
			name:      "endLine before startLine is treated as single-line",
			doc:       "code()\n",
			startLine: 1,
			endLine:   0,
			wantOK:    true,
			wantStart: Position{Line: 0, Character: 0},
			wantEnd:   Position{Line: 0, Character: 6},
			wantConf:  ConfidenceLine,
		},

		// ── Out of range: drop, never clamp ──────────────────────────────────
		{name: "line zero is dropped", doc: "code()\n", startLine: 0, wantOK: false},
		{name: "negative line is dropped", doc: "code()\n", startLine: -3, wantOK: false},
		{name: "line past the end is dropped", doc: "code()\n", startLine: 99, wantOK: false},
		{
			// An empty document is one empty line, so this must behave exactly
			// like the blank-line case rather than being dropped. Treating them
			// differently would mean an empty file and a file containing a
			// single newline placed the same finding two different ways.
			name:      "empty document behaves like a blank line",
			doc:       "",
			startLine: 1,
			wantOK:    true,
			wantStart: Position{Line: 0, Character: 0},
			wantEnd:   Position{Line: 0, Character: 0},
			wantConf:  ConfidenceLine,
		},
		{name: "line 2 of an empty document is dropped", doc: "", startLine: 2, wantOK: false},

		// ── Secret narrowing ─────────────────────────────────────────────────
		{
			name:       "secret narrows past = and the quote",
			doc:        "AWS_SECRET = \"AKIAIOSFODNN7EXAMPLE\"\n",
			startLine:  1,
			opts:       Options{Kind: "secrets"},
			wantOK:     true,
			wantConf:   ConfidenceLine,
			wantSubstr: "AKIAIOSFODNN7EXAMPLE\"",
		},
		{
			name:       "secret narrows past a colon in YAML",
			doc:        "  api_key: ghp_000000000000\n",
			startLine:  1,
			opts:       Options{Kind: "secrets"},
			wantOK:     true,
			wantConf:   ConfidenceLine,
			wantSubstr: "ghp_000000000000",
		},
		{
			name:       "secret narrows past := in Go",
			doc:        "token := \"ghp_000000000000\"\n",
			startLine:  1,
			opts:       Options{Kind: "secrets"},
			wantOK:     true,
			wantConf:   ConfidenceLine,
			wantSubstr: "ghp_000000000000\"",
		},
		{
			name:       "secret with a single quote",
			doc:        "password = 'hunter2'\n",
			startLine:  1,
			opts:       Options{Kind: "secrets"},
			wantOK:     true,
			wantConf:   ConfidenceLine,
			wantSubstr: "hunter2'",
		},
		{
			name:      "secret with no separator keeps the whole span",
			doc:       "AKIAIOSFODNN7EXAMPLE\n",
			startLine: 1,
			opts:      Options{Kind: "secrets"},
			wantOK:    true,
			wantStart: Position{Line: 0, Character: 0},
			wantEnd:   Position{Line: 0, Character: 20},
			wantConf:  ConfidenceLine,
		},
		{
			name:      "separator at the end of the line keeps the whole span",
			doc:       "password =\n",
			startLine: 1,
			opts:      Options{Kind: "secrets"},
			wantOK:    true,
			wantStart: Position{Line: 0, Character: 0},
			wantEnd:   Position{Line: 0, Character: 10},
			wantConf:  ConfidenceLine,
		},
		{
			name:      "non-secret kinds are not narrowed",
			doc:       "password = 'hunter2'\n",
			startLine: 1,
			opts:      Options{Kind: "sast"},
			wantOK:    true,
			wantStart: Position{Line: 0, Character: 0},
			wantEnd:   Position{Line: 0, Character: 20},
			wantConf:  ConfidenceLine,
		},
		{
			name:      "multi-line secret is not narrowed",
			doc:       "key = -----BEGIN KEY-----\nMIIBOwIBAAJ\n-----END KEY-----\n",
			startLine: 1,
			endLine:   3,
			opts:      Options{Kind: "secrets"},
			wantOK:    true,
			wantStart: Position{Line: 0, Character: 0},
			wantConf:  ConfidenceLine,
		},
		{
			name:       "secret after CJK narrows at the right unit offset",
			doc:        "密钥 = \"ghp_000000000000\"\n",
			startLine:  1,
			opts:       Options{Kind: "secrets"},
			wantOK:     true,
			wantConf:   ConfidenceLine,
			wantSubstr: "ghp_000000000000\"",
		},

		// ── Snippet shapes ───────────────────────────────────────────────────
		{
			name:      "blank snippet is ignored",
			doc:       "  code()\n",
			startLine: 1,
			opts:      Options{Snippet: "   \n  \n"},
			wantOK:    true,
			wantStart: Position{Line: 0, Character: 2},
			wantConf:  ConfidenceLine,
		},
		{
			name:       "snippet padded with blank context lines still matches",
			doc:        "  eval(x);\n",
			startLine:  1,
			opts:       Options{Kind: "sast", Snippet: "\n\n  eval(x);\n\n"},
			wantOK:     true,
			wantConf:   ConfidenceExact,
			wantSubstr: "eval(x);",
		},
		{
			name:       "snippet occurring twice matches the first",
			doc:        "eval(x); eval(x);\n",
			startLine:  1,
			opts:       Options{Kind: "sast", Snippet: "eval(x);"},
			wantOK:     true,
			wantStart:  Position{Line: 0, Character: 0},
			wantEnd:    Position{Line: 0, Character: 8},
			wantConf:   ConfidenceExact,
			wantSubstr: "eval(x);",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := SplitLines(c.doc)
			endLine := c.endLine
			if endLine == 0 && c.name != "endLine before startLine is treated as single-line" {
				endLine = c.startLine
			}

			got, ok := Columns(doc, c.startLine, endLine, c.opts)
			require.Equal(t, c.wantOK, ok, "ok")
			if !ok {
				return
			}

			if c.wantConf != "" {
				require.Equal(t, c.wantConf, got.Confidence, "confidence")
			}
			if c.wantStart != (Position{}) || c.wantConf == ConfidenceLine {
				if c.wantStart != (Position{}) || c.wantEnd != (Position{}) {
					require.Equal(t, c.wantStart, got.Range.Start, "start")
				}
			}
			if c.wantEnd != (Position{}) {
				require.Equal(t, c.wantEnd, got.Range.End, "end")
			}
			if c.wantSubstr != "" {
				require.Equal(t, c.wantSubstr, textOf(doc, got.Range),
					"the range should cover exactly this text")
			}

			requireSaneRange(t, doc, got.Range)
		})
	}
}

// textOf extracts the document text a range covers, which is how a test states
// intent readably instead of asserting two integers and hoping.
func textOf(doc []string, r Range) string {
	if r.Start.Line == r.End.Line {
		line := doc[r.Start.Line]
		s, _ := byteOffset(line, r.Start.Character)
		e, _ := byteOffset(line, r.End.Character)
		return line[s:e]
	}
	first := doc[r.Start.Line]
	s, _ := byteOffset(first, r.Start.Character)
	out := first[s:]
	for i := r.Start.Line + 1; i < r.End.Line; i++ {
		out += "\n" + doc[i]
	}
	last := doc[r.End.Line]
	e, _ := byteOffset(last, r.End.Character)
	return out + "\n" + last[:e]
}

// requireSaneRange enforces the invariants an editor relies on. A range that
// violates one of these is rejected by VS Code, or worse, silently rendered in
// the wrong place.
func requireSaneRange(t *testing.T, doc []string, r Range) {
	t.Helper()
	require.GreaterOrEqual(t, r.Start.Line, 0, "start line is non-negative")
	require.Less(t, r.Start.Line, len(doc), "start line is within the document")
	require.Less(t, r.End.Line, len(doc), "end line is within the document")
	require.GreaterOrEqual(t, r.End.Line, r.Start.Line, "end is not before start")
	if r.Start.Line == r.End.Line {
		require.GreaterOrEqual(t, r.End.Character, r.Start.Character, "end column is not before start")
	}
	require.LessOrEqual(t, r.Start.Character, utf16Len(doc[r.Start.Line]), "start column within the line")
	require.LessOrEqual(t, r.End.Character, utf16Len(doc[r.End.Line]), "end column within the line")
}

func TestSplitLines(t *testing.T) {
	require.Equal(t, []string{"a", "b", ""}, SplitLines("a\nb\n"))
	require.Equal(t, []string{"a", "b", ""}, SplitLines("a\r\nb\r\n"), "CRLF must not leave carriage returns")
	require.Equal(t, []string{"a"}, SplitLines("\uFEFFa"), "a BOM must not shift line 1 by one column")
	require.Equal(t, []string{""}, SplitLines(""))
}

func TestCRLFDoesNotWidenTheRange(t *testing.T) {
	// A carriage return left on the line makes every range one character too
	// wide, on every finding in a Windows-authored file.
	doc := SplitLines("  eval(x);\r\n")
	got, ok := Columns(doc, 1, 1, Options{Kind: "sast"})
	require.True(t, ok)
	require.Equal(t, 2, got.Range.Start.Character)
	require.Equal(t, 10, got.Range.End.Character)
	require.Equal(t, "eval(x);", textOf(doc, got.Range))
}

func TestUTF16Len(t *testing.T) {
	require.Equal(t, 0, utf16Len(""))
	require.Equal(t, 5, utf16Len("plain"))
	require.Equal(t, 2, utf16Len("说明"), "CJK are one UTF-16 unit each")
	require.Equal(t, 2, utf16Len("😀"), "emoji are a surrogate pair")
	require.Equal(t, 4, utf16Len("😀😀"))
	require.Equal(t, 3, utf16Len("a😀"))
}

func TestByteOffsetRoundTrip(t *testing.T) {
	for _, s := range []string{"", "plain", "说明 text", "a😀b", "😀😀😀", "tab\there"} {
		t.Run(fmt.Sprintf("%q", s), func(t *testing.T) {
			units := utf16Len(s)
			off, ok := byteOffset(s, units)
			require.True(t, ok)
			require.Equal(t, len(s), off, "the full length must round-trip")

			off, ok = byteOffset(s, 0)
			require.True(t, ok)
			require.Equal(t, 0, off)
		})
	}
}

func TestByteOffsetRejectsMidSurrogate(t *testing.T) {
	// Offset 1 lands inside the surrogate pair for 😀. There is no byte offset
	// that corresponds, so it must be reported rather than rounded.
	_, ok := byteOffset("😀", 1)
	require.False(t, ok)
}

func TestValidUTF8(t *testing.T) {
	require.True(t, ValidUTF8("hello 😀 说明"))
	require.False(t, ValidUTF8(string([]byte{0xff, 0xfe})))
}
