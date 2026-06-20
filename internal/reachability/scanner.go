package reachability

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/vulnetix/cli/v3/internal/treesitter"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// MaxFileSize is the largest file the scanner will parse. Files above
// this threshold are silently skipped to keep memory bounded.
const MaxFileSize = 4 * 1024 * 1024 // 4 MiB

// ScanRequest groups the inputs to one reachability scan.
type ScanRequest struct {
	ProjectRoot string
	Ecosystem   string
	Package     string
	// Queries from vdb-api's GET /vuln/{id}/tree-sitter response.
	Queries []vdb.TreeSitterQuery
	Mode    Mode
}

// Scan runs the queries against the project. Direct matches come from
// files inside the installed-package directory; transitive matches
// come from the rest of the project tree (excluding the install
// directory and standard build/cache folders).
func Scan(ctx context.Context, engine *Engine, req ScanRequest) (*Result, error) {
	if req.Mode == ModeOff {
		return &Result{}, nil
	}
	if len(req.Queries) == 0 {
		return &Result{}, nil
	}
	if engine == nil {
		engine = NewEngine()
	}

	byLang := groupQueriesByLanguage(req.Queries)
	if len(byLang) == 0 {
		return &Result{}, nil
	}

	res := &Result{Executed: map[string]bool{}}
	for _, qs := range byLang {
		res.QueriesRun += len(qs)
	}

	installDir := ""
	if req.Mode.Includes(ModeDirect) {
		installDir = InstallPath(req.ProjectRoot, req.Ecosystem, req.Package)
		if installDir == "" {
			res.SkippedDirect = fmt.Sprintf("install directory for %s/%s not found", req.Ecosystem, req.Package)
		} else {
			matches, err := scanRoot(ctx, engine, installDir, byLang, nil, res.Executed)
			if err != nil {
				return nil, fmt.Errorf("direct scan: %w", err)
			}
			res.Direct = matches
		}
	}

	if req.Mode.Includes(ModeTransitive) {
		if req.ProjectRoot == "" {
			res.SkippedTransitive = "project root unknown"
		} else {
			skip := skipDirs()
			excludeAbs := ""
			if installDir != "" {
				excludeAbs, _ = filepath.Abs(installDir)
			}
			matches, err := scanRoot(ctx, engine, req.ProjectRoot, byLang, func(path string) bool {
				if excludeAbs != "" {
					abs, _ := filepath.Abs(path)
					if abs == excludeAbs || strings.HasPrefix(abs, excludeAbs+string(filepath.Separator)) {
						return true
					}
				}
				return false
			}, res.Executed)
			if err != nil {
				return nil, fmt.Errorf("transitive scan: %w", err)
			}
			// Mark mode by storing in Transitive bucket; the file paths
			// are already relative to projectRoot.
			res.Transitive = matches
			_ = skip // skipDirs is consulted inside scanRoot
		}
	}

	// Render paths relative to projectRoot for friendlier output.
	if req.ProjectRoot != "" {
		relativiseAll(req.ProjectRoot, res.Direct)
		relativiseAll(req.ProjectRoot, res.Transitive)
	}
	return res, nil
}

// QueryKey is the stable identity for a query: its server-provided hash when
// present, else name + normalised language. The engine records this key in
// Result.Executed for every query that actually compiled and ran against a
// source file, so callers can distinguish "ran but matched nothing" from
// "never ran" (unsupported language / no matching files / compile failure).
func QueryKey(q vdb.TreeSitterQuery) string {
	if q.QueryHash != "" {
		return q.QueryHash
	}
	return q.Name + ":" + string(treesitter.Normalise(q.Language))
}

func groupQueriesByLanguage(qs []vdb.TreeSitterQuery) map[treesitter.LanguageID][]vdb.TreeSitterQuery {
	out := make(map[treesitter.LanguageID][]vdb.TreeSitterQuery, 4)
	for _, q := range qs {
		id := treesitter.Normalise(q.Language)
		if id == "" || treesitter.Grammar(id) == nil {
			continue
		}
		out[id] = append(out[id], q)
	}
	return out
}

// scanRoot walks every source file under root and runs the matching
// language's queries against each. If excludePath returns true for an
// absolute path it (and its descendants if it is a directory) is
// skipped — used to exclude the install directory from a transitive
// sweep.
func scanRoot(
	ctx context.Context,
	engine *Engine,
	root string,
	byLang map[treesitter.LanguageID][]vdb.TreeSitterQuery,
	excludePath func(string) bool,
	executed map[string]bool,
) ([]Match, error) {
	if root == "" {
		return nil, nil
	}
	skip := skipDirs()

	// Phase 1 — walk the tree once (deterministic order) collecting the files
	// to analyse. The dir-skip / exclude / language / size filters are applied
	// here exactly as before; only the per-file read + query execution is
	// deferred to Phase 2 so it can run concurrently.
	type fileTask struct {
		path string
		lang treesitter.LanguageID
	}
	var tasks []fileTask
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrPermission) {
				return nil
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			name := d.Name()
			if path != root {
				if _, drop := skip[name]; drop {
					return filepath.SkipDir
				}
				if excludePath != nil && excludePath(path) {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if excludePath != nil && excludePath(path) {
			return nil
		}
		lang := treesitter.LanguageForPath(path)
		if lang == "" {
			return nil
		}
		if _, ok := byLang[lang]; !ok {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() == 0 || info.Size() > MaxFileSize {
			return nil
		}
		tasks = append(tasks, fileTask{path: path, lang: lang})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(tasks) == 0 {
		return nil, nil
	}

	// Phase 2 — run each file's queries. Results are stored per-task so the
	// merge in Phase 3 can reassemble them in the exact walk order, making the
	// output byte-identical to the former serial loop regardless of how many
	// workers run. The engine is safe for concurrent use (pooled parsers).
	perFileMatches := make([][]Match, len(tasks))
	perFileExecuted := make([][]string, len(tasks))
	conc := reachabilityConcurrency()
	if conc <= 1 || len(tasks) == 1 {
		for i, t := range tasks {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			perFileMatches[i], perFileExecuted[i] = runFileQueries(ctx, engine, t.path, t.lang, byLang[t.lang])
		}
	} else {
		sem := make(chan struct{}, conc)
		var wg sync.WaitGroup
		for i, t := range tasks {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(i int, t fileTask) {
				defer wg.Done()
				defer func() { <-sem }()
				perFileMatches[i], perFileExecuted[i] = runFileQueries(ctx, engine, t.path, t.lang, byLang[t.lang])
			}(i, t)
		}
		wg.Wait()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}

	// Phase 3 — merge in walk order: concatenate matches and union the executed
	// query-key set (order-independent).
	var out []Match
	for i := range tasks {
		out = append(out, perFileMatches[i]...)
		if executed != nil {
			for _, k := range perFileExecuted[i] {
				executed[k] = true
			}
		}
	}
	return out, nil
}

// runFileQueries reads one source file and runs every query for its language,
// returning the matches (in query- then match-order) and the keys of the
// queries that actually compiled and ran (so the caller can mark them executed).
func runFileQueries(ctx context.Context, engine *Engine, path string, lang treesitter.LanguageID, qs []vdb.TreeSitterQuery) ([]Match, []string) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	var matches []Match
	var executed []string
	for _, q := range qs {
		ms, err := engine.Run(ctx, lang, src, q.QueryText)
		if err != nil {
			// Bad query for this grammar version; keep scanning.
			continue
		}
		// The query compiled and ran against this file — record it as genuinely
		// executed regardless of match count, so callers don't treat "no
		// matching files / unsupported language" as evidence of non-reachability.
		executed = append(executed, QueryKey(q))
		for _, m := range ms {
			matches = append(matches, Match{
				File:      path,
				StartLine: m.StartLine,
				EndLine:   m.EndLine,
				Query:     q.Name,
				Language:  string(lang),
				Captures:  m.Captures,
			})
		}
	}
	return matches, executed
}

// reachabilityConcurrency is how many source files the tree-sitter scan analyses
// in parallel. Defaults to GOMAXPROCS; VULNETIX_REACHABILITY_CONCURRENCY
// overrides it (clamped 1–32; 1 = the legacy strictly-serial walk).
func reachabilityConcurrency() int {
	n := runtime.GOMAXPROCS(0)
	if v := strings.TrimSpace(os.Getenv("VULNETIX_REACHABILITY_CONCURRENCY")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = parsed
		}
	}
	return min(max(n, 1), 32)
}

func relativiseAll(root string, matches []Match) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return
	}
	for i := range matches {
		abs, err := filepath.Abs(matches[i].File)
		if err != nil {
			continue
		}
		if rel, err := filepath.Rel(absRoot, abs); err == nil && !strings.HasPrefix(rel, "..") {
			matches[i].File = rel
		}
	}
}
