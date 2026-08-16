package ghasetup

// Repository detection for `vulnetix gha setup --detect`.
//
// Wiring scanners by hand does not scale past one repository: someone has to
// know that this one is Go with Terraform and that one is TypeScript with a
// Dockerfile, and the answer goes stale the moment a language is added. One
// walk of the tree answers it for every tool in the catalog at once.

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// scanDirSkip are directories a repository's own sources are never in, and
// which are large enough that walking them is the whole cost of the command.
// vendor/ and node_modules/ also carry other projects' manifests, which is how
// a Go service gets a Ruby scanner wired into it.
var scanDirSkip = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".venv": true,
	"venv": true, "target": true, "dist": true, "build": true,
	".terraform": true, "__pycache__": true, ".next": true, ".nuxt": true,
	"coverage": true, ".gradle": true, ".idea": true, ".vscode": true,

	// Fixture trees are the other big source of wrong answers, and a subtler
	// one: a Go CLI with a composer.json under testdata/ is not a PHP project,
	// but detection by file presence cannot tell the difference. Go already
	// treats testdata/ as "not code"; the rest follow the same convention.
	"testdata": true, "test_data": true, "fixtures": true,
	"__fixtures__": true, "third_party": true, "thirdparty": true,
	".vulnetix": true, "tmp": true, ".cache": true,
}

// scanMaxDepth bounds the walk. A manifest that identifies a project's language
// lives near its root; one buried eight levels down is a fixture.
const scanMaxDepth = 6

// RepoSignals is what a repository contains, reduced to the two questions the
// catalog asks: which files are present, and which extensions appear.
type RepoSignals struct {
	Files      map[string]bool
	Extensions map[string]bool
}

// ScanRepo walks a repository and records the signals the catalog matches on.
func ScanRepo(root string) (*RepoSignals, error) {
	sig := &RepoSignals{
		Files:      map[string]bool{},
		Extensions: map[string]bool{},
	}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable subtree is not a reason to fail the whole scan;
			// worst case a tool that would have matched is not selected.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}

			return nil
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		if rel == "." {
			return nil
		}

		if d.IsDir() {
			if scanDirSkip[d.Name()] {
				return fs.SkipDir
			}
			if strings.Count(rel, string(filepath.Separator)) >= scanMaxDepth {
				return fs.SkipDir
			}
			// Directories are matchable too: zizmor is selected by
			// .github/workflows existing, not by any file inside it.
			sig.Files[d.Name()] = true
			sig.Files[filepath.ToSlash(rel)] = true

			return nil
		}

		sig.Files[d.Name()] = true
		if ext := strings.ToLower(filepath.Ext(d.Name())); ext != "" {
			sig.Extensions[ext] = true
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// Matches reports whether a tool applies to a repository with these signals.
func (d Detect) Matches(sig *RepoSignals) bool {
	if d.Manual || sig == nil {
		return false
	}
	if d.Always {
		return true
	}
	for _, f := range d.Files {
		if sig.Files[f] || sig.Files[strings.TrimPrefix(f, "./")] {
			return true
		}
	}
	for _, e := range d.Extensions {
		if sig.Extensions[strings.ToLower(e)] {
			return true
		}
	}

	return false
}

// DetectTools returns the catalog ids that apply to the repository at root,
// sorted, along with the signals they were chosen from.
func DetectTools(c *Catalog, root string) ([]string, *RepoSignals, error) {
	sig, err := ScanRepo(root)
	if err != nil {
		return nil, nil, err
	}

	var out []string
	for i := range c.Tools {
		if c.Tools[i].Detect.Matches(sig) {
			out = append(out, c.Tools[i].ID)
		}
	}
	sort.Strings(out)

	return out, sig, nil
}

// ManualTools returns the ids --detect will never select, with the reason, so
// the command can say what it left out rather than silently narrowing the set.
func ManualTools(c *Catalog) []string {
	var out []string
	for i := range c.Tools {
		if c.Tools[i].Detect.Manual {
			out = append(out, c.Tools[i].ID)
		}
	}
	sort.Strings(out)

	return out
}

// RepoRootOrCwd is a convenience for callers that already resolved a root.
func RepoRootOrCwd(root string) string {
	if root != "" {
		return root
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "."
	}

	return cwd
}
