package sast

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The rule pages render through Goldmark with raw HTML allowed, so a rule doc
// that writes <script> in prose instead of `<script>` emits a real script
// element, and Hugo's minifier then fails the whole site build parsing the
// sentence after it as JavaScript. That is how one page (VNX-933) stopped the
// docs deploy. Tags are only safe inside code spans and fenced blocks.
var rawActiveTag = regexp.MustCompile(`(?i)<(script|style|iframe|object|embed)\b`)

func TestRuleDocsWriteTagsAsCode(t *testing.T) {
	dir := filepath.Join("..", "..", "website", "content", "docs", "sast-rules")
	paths, err := filepath.Glob(filepath.Join(dir, "*.md"))
	if err != nil || len(paths) == 0 {
		t.Skipf("no rule docs at %s", dir)
	}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for n, line := range proseLines(string(b)) {
			if rawActiveTag.MatchString(line) {
				t.Errorf("%s:%d writes an HTML tag outside code; wrap it in backticks: %s", filepath.Base(p), n, strings.TrimSpace(line))
			}
		}
	}
}

// proseLines returns the body lines outside front matter and fenced blocks,
// with inline code spans removed, keyed by 1-based line number.
func proseLines(doc string) map[int]string {
	out := map[int]string{}
	lines := strings.Split(doc, "\n")
	inFront, inFence := false, false
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if i == 0 && t == "---" {
			inFront = true
			continue
		}
		if inFront {
			if t == "---" {
				inFront = false
			}
			continue
		}
		if strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~") {
			inFence = !inFence
			continue
		}
		if inFence || strings.HasPrefix(l, "    ") || strings.HasPrefix(l, "\t") {
			continue
		}
		out[i+1] = stripCodeSpans(l)
	}
	return out
}

// stripCodeSpans removes inline code as CommonMark reads it: a run of N
// backticks opens a span that only a run of exactly N backticks closes, so
// `` ` `` is one span holding a backtick.
func stripCodeSpans(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '`' {
			b.WriteByte(s[i])
			i++
			continue
		}
		n := 0
		for i+n < len(s) && s[i+n] == '`' {
			n++
		}
		closed := -1
		for j := i + n; j < len(s); {
			if s[j] != '`' {
				j++
				continue
			}
			m := 0
			for j+m < len(s) && s[j+m] == '`' {
				m++
			}
			if m == n {
				closed = j + m
				break
			}
			j += m
		}
		if closed < 0 {
			// An unclosed run is literal text.
			b.WriteString(s[i : i+n])
			i += n
			continue
		}
		i = closed
	}
	return b.String()
}
