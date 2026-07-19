package sast

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// nosec source-suppression pass. After rego evaluation and before report output,
// findings whose source line carries a `# nosec` / `// nosec` comment are
// dropped. Semantics (gosec-compatible):
//
//   - bare `nosec` on a finding's line   → drop all findings on that line
//   - `nosec vnx-315,vnx-320`            → drop only those rule ids on that line
//   - bare `nosec` on line 1 of a file   → drop every finding in that file
//
// A rule-specific line-1 directive (`# nosec vnx-315` on line 1) whole-file
// skips only the listed rule ids.
//
// The token is matched inside a `#` or `//` comment (any position on the line),
// and also `--` (SQL/Lua) and `;` (ini) trailing comments, so the one pass
// covers every language the rego engine emits findings for.

var nosecRe = regexp.MustCompile(`(?i)(?:#|//|--|;)\s*nosec\b([\w\-,\s]*)`)

// nosecDirective is a parsed nosec comment: whether it targets all rules or a
// specific set of rule ids.
type nosecDirective struct {
	all     bool
	ruleIDs map[string]bool
}

// ApplyNosec filters findings against nosec source comments and returns the
// kept findings plus the number dropped. rootPath anchors the (possibly
// relative) ArtifactURI values to disk.
func ApplyNosec(findings []Finding, rootPath string) ([]Finding, int) {
	if len(findings) == 0 {
		return findings, 0
	}

	// Cache per-file line directives so each file is read at most once.
	fileCache := map[string]map[int]nosecDirective{}
	fileLevel := map[string]nosecDirective{} // line-1 whole-file directive
	scanned := map[string]bool{}

	load := func(uri string) (map[int]nosecDirective, nosecDirective) {
		if scanned[uri] {
			return fileCache[uri], fileLevel[uri]
		}
		scanned[uri] = true
		byLine, whole := scanNosec(resolvePath(rootPath, uri))
		fileCache[uri] = byLine
		fileLevel[uri] = whole
		return byLine, whole
	}

	kept := findings[:0]
	dropped := 0
	for _, f := range findings {
		if f.ArtifactURI == "" {
			kept = append(kept, f)
			continue
		}
		byLine, whole := load(f.ArtifactURI)
		if nosecCovers(whole, f.RuleID) {
			dropped++
			continue
		}
		if directiveOnLines(byLine, f, f.RuleID) {
			dropped++
			continue
		}
		kept = append(kept, f)
	}
	return kept, dropped
}

func directiveOnLines(byLine map[int]nosecDirective, f Finding, ruleID string) bool {
	if byLine == nil {
		return false
	}
	start := f.StartLine
	end := f.EndLine
	if end < start {
		end = start
	}
	for ln := start; ln <= end; ln++ {
		if d, ok := byLine[ln]; ok && nosecCovers(d, ruleID) {
			return true
		}
	}
	return false
}

func nosecCovers(d nosecDirective, ruleID string) bool {
	if !d.all && len(d.ruleIDs) == 0 {
		return false
	}
	if d.all {
		return true
	}
	return d.ruleIDs[strings.ToLower(strings.TrimSpace(ruleID))]
}

// scanNosec reads a file and returns nosec directives keyed by line number,
// plus the file-level directive when line 1 carries nosec.
func scanNosec(path string) (map[int]nosecDirective, nosecDirective) {
	byLine := map[int]nosecDirective{}
	var whole nosecDirective

	f, err := os.Open(path)
	if err != nil {
		return byLine, whole
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	ln := 0
	for sc.Scan() {
		ln++
		m := nosecRe.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		d := parseNosecIDs(m[1])
		byLine[ln] = d
		if ln == 1 {
			whole = d
		}
	}
	return byLine, whole
}

// parseNosecIDs turns the text after `nosec` into a directive. Empty/whitespace
// means "all rules"; otherwise a comma/space-separated rule-id list.
func parseNosecIDs(rest string) nosecDirective {
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return nosecDirective{all: true}
	}
	ids := map[string]bool{}
	for _, tok := range strings.FieldsFunc(rest, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		tok = strings.ToLower(strings.TrimSpace(tok))
		if tok != "" {
			ids[tok] = true
		}
	}
	if len(ids) == 0 {
		return nosecDirective{all: true}
	}
	return nosecDirective{ruleIDs: ids}
}

func resolvePath(root, uri string) string {
	uri = strings.TrimPrefix(uri, "file://")
	if filepath.IsAbs(uri) {
		return uri
	}
	return filepath.Join(root, uri)
}
