package reachability

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vulnetix/cli/internal/treesitter"
	"github.com/vulnetix/cli/pkg/vdb"
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

	res := &Result{}
	for _, qs := range byLang {
		res.QueriesRun += len(qs)
	}

	installDir := ""
	if req.Mode.Includes(ModeDirect) {
		installDir = InstallPath(req.ProjectRoot, req.Ecosystem, req.Package)
		if installDir == "" {
			res.SkippedDirect = fmt.Sprintf("install directory for %s/%s not found", req.Ecosystem, req.Package)
		} else {
			matches, err := scanRoot(ctx, engine, installDir, byLang, nil)
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
			})
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
) ([]Match, error) {
	if root == "" {
		return nil, nil
	}
	skip := skipDirs()
	var out []Match

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
		qs, ok := byLang[lang]
		if !ok {
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
		for _, q := range qs {
			matches, err := engine.Run(ctx, lang, src, q.QueryText)
			if err != nil {
				// Bad query for this grammar version; keep scanning.
				continue
			}
			for _, m := range matches {
				out = append(out, Match{
					File:      path,
					StartLine: m.StartLine,
					EndLine:   m.EndLine,
					Query:     q.Name,
					Language:  string(lang),
					Captures:  m.Captures,
				})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
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
