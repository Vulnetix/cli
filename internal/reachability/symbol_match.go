package reachability

// Symbol-level grep matcher — the lower-efficacy reachability fallback the
// CLI runs against the project source when tree-sitter queries are missing
// for a CVE. The server-side cli.sca response carries
// vulnetix:affectedRoutines / vulnetix:affectedFiles / vulnetix:affectedModules
// for every tier; this file consumes those into a single literal-text regex
// per file extension and walks the project root the same way scanRoot does
// for tree-sitter, sharing the skipDirs + MaxFileSize budgets.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// SymbolMatch is one grep hit during the fallback pass. The Reachability
// label this powers is intentionally named "semantic" — see docs site for
// the full meaning, but it's the "your code imports/references the affected
// element by name" signal: lower efficacy than a tree-sitter AST match but a
// strong indicator the dep is actually used rather than a phantom go.sum
// entry.
type SymbolMatch struct {
	File   string
	Line   int    // 1-indexed source line of the match (0 for file-name hits)
	Symbol string // the routine/file/module name that matched
	Kind   string // "routine" | "file" | "module"
}

// SymbolMatchRequest is the input to MatchAffectedSymbols. Inputs is a flat
// slice — one entry per CVE — carrying the symbol lists the server returned.
// The CLI receives a reverse map cve→[hits] so it can stamp
// Reachability="grep-match" per CVE.
type SymbolMatchRequest struct {
	ProjectRoot string
	Inputs      []CveSymbols
}

// CveSymbols groups the three symbol lists for one CVE.
type CveSymbols struct {
	CveID    string
	Routines []string
	Files    []string
	Modules  []string
}

// SymbolMatchResult is the cve→hits output.
type SymbolMatchResult struct {
	HitsByCVE map[string][]SymbolMatch
}

// MatchAffectedSymbols walks projectRoot once and tests every text file
// against a single compiled OR-regex of every quality-filtered routine/module
// name across all CVEs. File-name hits use simple Base() suffix matching on
// the walked path itself (no file-content scan needed). The match is purely
// literal — no language awareness beyond an extension allowlist that mirrors
// the tree-sitter scanner's view of "source files we should look at".
//
// Quality threshold for routine + module names:
//   - length >= 5 AND
//   - contains at least one capital letter, dot, or underscore
//
// Short / lowercase English words like "open" or "parse" would false-positive
// almost everywhere; the threshold removes them up front. File-name entries
// are matched verbatim regardless of length — they're path-shaped already.
func MatchAffectedSymbols(ctx context.Context, req SymbolMatchRequest) (*SymbolMatchResult, error) {
	if req.ProjectRoot == "" {
		return &SymbolMatchResult{HitsByCVE: map[string][]SymbolMatch{}}, nil
	}
	if len(req.Inputs) == 0 {
		return &SymbolMatchResult{HitsByCVE: map[string][]SymbolMatch{}}, nil
	}

	// Build symbol → []cve reverse indexes, separately for routines/modules
	// (regex-matched against file contents) and files (matched against the
	// file path itself).
	routineToCVEs := map[string][]string{}
	moduleToCVEs := map[string][]string{}
	fileToCVEs := map[string][]string{}
	for _, cs := range req.Inputs {
		for _, r := range cs.Routines {
			if isQualitySymbol(r) {
				routineToCVEs[r] = appendUnique(routineToCVEs[r], cs.CveID)
			}
		}
		for _, m := range cs.Modules {
			if isQualitySymbol(m) {
				moduleToCVEs[m] = appendUnique(moduleToCVEs[m], cs.CveID)
			}
		}
		for _, f := range cs.Files {
			f = strings.TrimSpace(f)
			if f == "" {
				continue
			}
			fileToCVEs[f] = appendUnique(fileToCVEs[f], cs.CveID)
		}
	}

	// Combine routines + modules into a single alternation since their hits
	// look identical to the matcher; we tag by kind on lookup.
	bodyNames := make([]string, 0, len(routineToCVEs)+len(moduleToCVEs))
	for n := range routineToCVEs {
		bodyNames = append(bodyNames, n)
	}
	for n := range moduleToCVEs {
		bodyNames = append(bodyNames, n)
	}

	var bodyRE *regexp.Regexp
	if len(bodyNames) > 0 {
		// Use word boundaries to keep `Foo` from matching `FooBar`, and
		// escape every literal so a symbol with regex metacharacters
		// (signature tokens like `<T>`) doesn't break the alternation.
		escaped := make([]string, len(bodyNames))
		for i, n := range bodyNames {
			escaped[i] = regexp.QuoteMeta(n)
		}
		bodyRE = regexp.MustCompile(`\b(` + strings.Join(escaped, "|") + `)\b`)
	}

	result := &SymbolMatchResult{HitsByCVE: map[string][]SymbolMatch{}}
	addHit := func(cves []string, hit SymbolMatch) {
		for _, c := range cves {
			result.HitsByCVE[c] = append(result.HitsByCVE[c], hit)
		}
	}

	skip := skipDirs()
	err := filepath.WalkDir(req.ProjectRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, os.ErrPermission) {
				return nil
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if path != req.ProjectRoot {
				if _, drop := skip[d.Name()]; drop {
					return filepath.SkipDir
				}
			}
			return nil
		}

		// File-name hits: exact basename or suffix match (common for paths
		// like "src/foo/bar.c" listed in programFiles).
		base := filepath.Base(path)
		for f, cves := range fileToCVEs {
			if f == base || strings.HasSuffix(path, f) {
				addHit(cves, SymbolMatch{File: path, Symbol: f, Kind: "file"})
			}
		}

		// Content scan only for files that look like source we'd analyse.
		if bodyRE == nil {
			return nil
		}
		if !looksLikeSource(path) {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() == 0 || info.Size() > MaxFileSize {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		// Find all symbol hits in this file. A single file might mention
		// many distinct symbols — emit one SymbolMatch per (file, symbol)
		// at the first source line where the symbol appears. The line
		// lookup is one O(n) pass since FindAllSubmatchIndex returns
		// byte offsets.
		seenInFile := map[string]bool{}
		for _, idx := range bodyRE.FindAllSubmatchIndex(src, -1) {
			if len(idx) < 4 {
				continue
			}
			sym := string(src[idx[2]:idx[3]])
			if seenInFile[sym] {
				continue
			}
			seenInFile[sym] = true
			line := byteOffsetToLine(src, idx[0])
			if cves, ok := routineToCVEs[sym]; ok {
				addHit(cves, SymbolMatch{File: path, Line: line, Symbol: sym, Kind: "routine"})
			}
			if cves, ok := moduleToCVEs[sym]; ok {
				addHit(cves, SymbolMatch{File: path, Line: line, Symbol: sym, Kind: "module"})
			}
		}
		return nil
	})
	if err != nil {
		return result, err
	}
	return result, nil
}

// isQualitySymbol rejects short, all-lowercase English-style names that would
// false-positive in any large codebase. We keep names that look code-shaped:
// they contain at least one capital letter (CamelCase), a dot (foo.bar.baz),
// an underscore (snake_case), or a slash (import paths like
// "golang.org/x/crypto"). Anything ≥5 chars with one of those markers passes.
func isQualitySymbol(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 5 {
		return false
	}
	for _, r := range s {
		if unicode.IsUpper(r) || r == '.' || r == '_' || r == '/' {
			return true
		}
	}
	return false
}

// looksLikeSource is a conservative extension allowlist mirroring what the
// tree-sitter scanner already accepts. We don't want to grep binaries or the
// massive node_modules JSON files.
func looksLikeSource(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go", ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
		".java", ".kt", ".scala", ".rb", ".php", ".rs", ".swift",
		".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx", ".m", ".mm",
		".cs", ".dart", ".ex", ".exs", ".erl", ".clj", ".cljs", ".lua",
		".pl", ".pm", ".sh", ".bash", ".zsh", ".groovy":
		return true
	}
	return false
}

// byteOffsetToLine returns the 1-indexed line number for the given byte
// offset in src. Used to convert regex match positions into the line:col
// format users expect in the Semantic Reachability output section.
func byteOffsetToLine(src []byte, off int) int {
	if off < 0 {
		return 0
	}
	if off > len(src) {
		off = len(src)
	}
	line := 1
	for i := 0; i < off; i++ {
		if src[i] == '\n' {
			line++
		}
	}
	return line
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
