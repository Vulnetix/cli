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
	"sync"
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

	// Phase 1 — walk the tree once (deterministic order) collecting every file
	// plus its size. The dir-skip filter is applied here exactly as before; the
	// per-file matching is deferred to Phase 2 so it can run concurrently.
	type symFile struct {
		path string
		base string
		size int64
	}
	skip := skipDirs()
	var files []symFile
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
		var size int64
		if info, err := d.Info(); err == nil {
			size = info.Size()
		}
		files = append(files, symFile{path: path, base: filepath.Base(path), size: size})
		return nil
	})
	if err != nil {
		return result, err
	}
	if len(files) == 0 {
		return result, nil
	}

	// matchFile produces one file's hits in the same order the serial walk did:
	// file-name hits first, then content (routine/module) hits in regex order.
	// It reads only shared read-only state (the reverse indexes + bodyRE) plus a
	// file-local seen set, so it is safe to run concurrently.
	type hitPair struct {
		cves []string
		hit  SymbolMatch
	}
	matchFile := func(f symFile) []hitPair {
		var hits []hitPair
		// File-name hits: exact basename or suffix match (common for paths
		// like "src/foo/bar.c" listed in programFiles).
		for name, cves := range fileToCVEs {
			if name == f.base || strings.HasSuffix(f.path, name) {
				hits = append(hits, hitPair{cves: cves, hit: SymbolMatch{File: f.path, Symbol: name, Kind: "file"}})
			}
		}
		// Content scan only for source-looking files within the size budget.
		if bodyRE == nil || !looksLikeSource(f.path) || f.size == 0 || f.size > MaxFileSize {
			return hits
		}
		src, err := os.ReadFile(f.path)
		if err != nil {
			return hits
		}
		// Emit one SymbolMatch per (file, symbol) at the first source line
		// where the symbol appears. The line lookup is one O(n) pass since
		// FindAllSubmatchIndex returns byte offsets.
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
				hits = append(hits, hitPair{cves: cves, hit: SymbolMatch{File: f.path, Line: line, Symbol: sym, Kind: "routine"}})
			}
			if cves, ok := moduleToCVEs[sym]; ok {
				hits = append(hits, hitPair{cves: cves, hit: SymbolMatch{File: f.path, Line: line, Symbol: sym, Kind: "module"}})
			}
		}
		return hits
	}

	// Phase 2 — match files concurrently, keeping each file's hits in a slot so
	// Phase 3 can merge them in the exact walk order (byte-identical to serial).
	perFile := make([][]hitPair, len(files))
	conc := reachabilityConcurrency()
	if conc <= 1 || len(files) == 1 {
		for i, f := range files {
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			perFile[i] = matchFile(f)
		}
	} else {
		sem := make(chan struct{}, conc)
		var wg sync.WaitGroup
		for i, f := range files {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(i int, f symFile) {
				defer wg.Done()
				defer func() { <-sem }()
				perFile[i] = matchFile(f)
			}(i, f)
		}
		wg.Wait()
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
	}

	// Phase 3 — merge in walk order.
	for i := range files {
		for _, hp := range perFile[i] {
			for _, c := range hp.cves {
				result.HitsByCVE[c] = append(result.HitsByCVE[c], hp.hit)
			}
		}
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
