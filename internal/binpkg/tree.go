package binpkg

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// defaultSkipDirs are pruned from every walk: version-control and dependency
// trees whose contents are already covered by manifest/installed-package
// discovery, and the kernel pseudo-filesystems that appear when a caller points
// this at a live root rather than an extracted image.
var defaultSkipDirs = []string{".git", ".hg", ".svn", "node_modules", "proc", "sys", "dev", ".vulnetix"}

// defaultMaxFileSize caps how large an artefact may be before it is skipped.
// Package metadata lives in small sections; a multi-gigabyte blob is a model
// weight or a disk image, not a binary worth parsing.
const defaultMaxFileSize = 1 << 30

// TreeOptions configures ScanTree.
type TreeOptions struct {
	Root string
	// SkipDirs are additional directory base names to prune.
	SkipDirs []string
	// MaxFileSize overrides defaultMaxFileSize when positive.
	MaxFileSize int64
	// Owners attributes each artefact to the OS package that installed it. Build
	// it with BuildOwnerIndex for a container root filesystem; leave nil
	// otherwise.
	Owners OwnerIndex
}

// Artifact is one compiled file that yielded package metadata or an ownership
// attribution.
type Artifact struct {
	Path       string
	Format     string
	Owner      *Owner
	Attributes map[string]string
	Packages   []Package
}

// TreeResult aggregates a whole-tree scan.
type TreeResult struct {
	Artifacts []Artifact
	Packages  []Package
	Edges     []Edge
	// Examined counts files that looked like a compiled artefact and were parsed.
	Examined int
	// Unowned counts artefacts that no package database claims. It is only
	// meaningful when Owners was supplied — an unclaimed binary in an image with a
	// package database is a file that arrived outside the package manager.
	Unowned []string
	Errors  []string
}

// ScanTree walks a directory tree and extracts embedded package metadata from
// every compiled artefact it finds. It is offline and read-only, and never
// returns an error for the tree as a whole: unreadable files are recorded in
// Errors so one bad file cannot abort an SBOM.
func ScanTree(opts TreeOptions) TreeResult {
	res := TreeResult{}
	root, err := filepath.Abs(opts.Root)
	if err != nil {
		root = opts.Root
	}
	maxSize := opts.MaxFileSize
	if maxSize <= 0 {
		maxSize = defaultMaxFileSize
	}
	skip := map[string]bool{}
	for _, d := range append(append([]string{}, defaultSkipDirs...), opts.SkipDirs...) {
		skip[d] = true
	}
	hasOwners := len(opts.Owners) > 0

	// Walk first, parse second. A container root filesystem holds thousands of
	// candidate artefacts, and reading each one's metadata is independent work, so
	// the parse is fanned out — but the results are written back by index, so the
	// output does not depend on which worker finished first.
	var candidates []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// A directory we cannot read is worth reporting once; a single
			// unreadable file is not.
			if d != nil && d.IsDir() {
				res.Errors = append(res.Errors, fmt.Sprintf("walk %s: %v", path, walkErr))
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if path != root && skip[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		// Symlinks are followed by neither the metadata readers nor the owner
		// index; skipping them also avoids counting the same binary twice.
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxSize || info.Size() < 4 {
			return nil
		}
		if !LooksExecutable(path) {
			return nil
		}
		candidates = append(candidates, path)
		return nil
	})
	res.Examined = len(candidates)

	results := make([]Result, len(candidates))
	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	if workers < 1 || len(candidates) < 2 {
		workers = 1
	}
	var wg sync.WaitGroup
	next := make(chan int)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				results[i] = FromArtifact(candidates[i])
			}
		}()
	}
	for i := range candidates {
		next <- i
	}
	close(next)
	wg.Wait()

	for i, path := range candidates {
		result := results[i]
		res.Errors = append(res.Errors, result.Errors...)

		var owner *Owner
		if hasOwners {
			if o, ok := opts.Owners.Lookup(root, path); ok {
				owner = &o
			}
		}
		if result.Empty() && owner == nil {
			continue
		}
		if hasOwners && owner == nil {
			res.Unowned = append(res.Unowned, path)
		}
		res.Artifacts = append(res.Artifacts, Artifact{
			Path: path, Format: result.Format, Owner: owner,
			Attributes: result.Attributes, Packages: result.Packages,
		})
		res.Packages = append(res.Packages, result.Packages...)
		res.Edges = append(res.Edges, result.Edges...)
	}

	res.Packages = Dedupe(res.Packages)
	res.Edges = mergeEdges(res.Edges)
	return res
}

// mergeEdges folds duplicate edge sets — the same module graph recovered from
// several binaries — into one entry per parent.
func mergeEdges(edges []Edge) []Edge {
	index := map[string]int{}
	var out []Edge
	for _, e := range edges {
		if e.From == "" || len(e.DependsOn) == 0 {
			continue
		}
		idx, ok := index[e.From]
		if !ok {
			index[e.From] = len(out)
			out = append(out, Edge{From: e.From, DependsOn: dedupeStrings(e.DependsOn)})
			continue
		}
		out[idx].DependsOn = dedupeStrings(append(out[idx].DependsOn, e.DependsOn...))
	}
	return out
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// RelativePath renders a path inside the scanned tree for use as a CycloneDX
// locator: slash-separated and relative to root when possible.
func RelativePath(root, path string) string {
	if rel, err := filepath.Rel(root, path); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(path)
}
