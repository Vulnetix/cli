package bom

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// collect.go gathers a set of SBOM documents to query across.
//
// Deliberately no persistent store. The questions a corpus answers — which
// projects carry this package, where is a component at inconsistent versions —
// are answered from documents that already exist on disk, and building an index
// per invocation is fast enough for the scale a CLI holds. A database would
// need schema migrations, staleness handling and a cache-invalidation story, to
// answer the same questions about the same files.
//
// Object storage is deliberately absent. Ingesting a bucket of a thousand SBOMs
// is a server's job, and the deployment labels (internal/cdx/deployment.go)
// exist so the server can answer at that scale. What this covers is the case a
// CLI is actually in: a directory of documents, a release's worth, a monorepo's.

// CollectOptions controls document collection.
type CollectOptions struct {
	// Paths are files, directories or globs to read.
	Paths []string
	// Recursive walks directories to any depth. Off by default: a directory of
	// SBOMs is the normal shape, and recursing into a source tree would sweep
	// up every package.json it finds.
	Recursive bool
	// MaxDepth bounds a recursive walk. Zero means unlimited.
	MaxDepth int
}

// Collected is the outcome of gathering documents.
type Collected struct {
	// Documents are the SBOMs that parsed.
	Documents []*Document
	// Skipped names files that were examined and were not SBOMs.
	Skipped []string
	// Failed names files that looked like SBOMs and could not be read, with
	// the reason. A corpus query over a partly-unreadable set must say so:
	// silently answering from fewer documents than the user pointed at is how
	// a "no results" answer becomes a wrong answer.
	Failed []FailedDocument
}

// FailedDocument is a file that looked like an SBOM but could not be parsed.
type FailedDocument struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Collect gathers SBOM documents from the given paths.
func Collect(opts CollectOptions) (*Collected, error) {
	if len(opts.Paths) == 0 {
		return nil, fmt.Errorf("no paths given")
	}

	out := &Collected{}
	seen := map[string]bool{}

	for _, p := range opts.Paths {
		matches, err := expandPath(p)
		if err != nil {
			return nil, err
		}
		for _, m := range matches {
			info, err := os.Stat(m)
			if err != nil {
				return nil, err
			}
			if info.IsDir() {
				if err := out.walkDir(m, opts, seen); err != nil {
					return nil, err
				}
				continue
			}
			out.consider(m, seen, true)
		}
	}

	// Deterministic order, so two runs over the same corpus agree and a diff of
	// their output shows real change.
	sort.Slice(out.Documents, func(i, j int) bool {
		return out.Documents[i].Source.Path < out.Documents[j].Source.Path
	})
	sort.Strings(out.Skipped)
	sort.Slice(out.Failed, func(i, j int) bool { return out.Failed[i].Path < out.Failed[j].Path })

	return out, nil
}

// expandPath resolves a glob, or returns the literal path.
func expandPath(p string) ([]string, error) {
	if !strings.ContainsAny(p, "*?[") {
		if _, err := os.Stat(p); err != nil {
			return nil, err
		}
		return []string{p}, nil
	}
	matches, err := filepath.Glob(p)
	if err != nil {
		return nil, fmt.Errorf("%q: %w", p, err)
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("%q matched no files", p)
	}
	return matches, nil
}

// walkDir collects documents from a directory.
func (c *Collected) walkDir(dir string, opts CollectOptions, seen map[string]bool) error {
	if !opts.Recursive {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			c.consider(filepath.Join(dir, e.Name()), seen, false)
		}
		return nil
	}

	base := strings.Count(filepath.Clean(dir), string(filepath.Separator))
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable subdirectory should not abort a corpus query over
			// the rest of the tree.
			if errors.Is(err, fs.ErrPermission) {
				return fs.SkipDir
			}
			return err
		}
		if d.IsDir() {
			if opts.MaxDepth > 0 {
				depth := strings.Count(filepath.Clean(path), string(filepath.Separator)) - base
				if depth >= opts.MaxDepth {
					return fs.SkipDir
				}
			}
			// A vendored dependency tree contains thousands of manifests and no
			// SBOMs worth reading.
			if skipDirName(d.Name()) && path != dir {
				return fs.SkipDir
			}
			return nil
		}
		c.consider(path, seen, false)
		return nil
	})
}

// skipDirName reports whether a directory is never worth walking for SBOMs.
func skipDirName(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", "target", "dist", "build", ".venv", "__pycache__":
		return true
	}
	return false
}

// consider reads one file, classifying it as a document, a skip or a failure.
//
// explicit distinguishes a file the user named from one found by walking. A
// named file that is not an SBOM is worth reporting as a failure — the user
// pointed at it — whereas one found in a directory is simply not an SBOM.
func (c *Collected) consider(path string, seen map[string]bool, explicit bool) {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	if seen[abs] {
		return
	}
	seen[abs] = true

	if !explicit && !looksLikeSBOMFile(path) {
		return
	}

	data, err := os.ReadFile(path)
	if err != nil {
		c.Failed = append(c.Failed, FailedDocument{Path: path, Reason: err.Error()})
		return
	}

	if Detect(data).Format == FormatUnknown {
		// Two different situations, and conflating them loses the one that
		// matters. Valid JSON that is not an SBOM is a skip: a corpus directory
		// holds config and reports alongside documents. Malformed JSON in a file
		// that was selected — named by the user, or named like an SBOM — is a
		// failure, because it is a document that should have been in the answer
		// and is not.
		if json.Valid(data) {
			c.Skipped = append(c.Skipped, path)
		} else {
			c.Failed = append(c.Failed, FailedDocument{
				Path: path, Reason: "not valid JSON",
			})
		}
		return
	}

	doc, err := LoadBytes(data, path)
	if err != nil {
		c.Failed = append(c.Failed, FailedDocument{Path: path, Reason: err.Error()})
		return
	}
	c.Documents = append(c.Documents, doc)
}

// looksLikeSBOMFile is the cheap filter applied when walking.
//
// Reading and sniffing every file in a tree is the honest approach and far too
// slow on a large one, so a walk considers only files whose name suggests an
// SBOM. A file the user named explicitly bypasses this — they said what it is.
func looksLikeSBOMFile(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	if !strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".jsonl") {
		return false
	}
	for _, marker := range []string{
		".cdx.", ".spdx.", "cyclonedx", "spdx", "sbom", "bom.", ".intoto.", "attestation",
	} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}
