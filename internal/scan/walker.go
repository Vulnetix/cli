package scan

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/vulnetix/cli/v3/internal/ecosystems"
	"github.com/vulnetix/cli/v3/internal/ignore"
)

// WalkOptions configures the filesystem walk behavior.
type WalkOptions struct {
	RootPath string
	MaxDepth int
	Excludes []string // glob patterns to exclude
	// RespectGitignore, when true, prunes files and directories matched by
	// .gitignore files (accumulated top-down). The sca path leaves this false
	// because dependency manifests routinely live in gitignored install dirs.
	RespectGitignore bool
}

// WalkForScanFiles walks the filesystem from root, up to maxDepth, looking for
// manifest files and potential SBOM documents.
func WalkForScanFiles(opts WalkOptions) ([]DetectedFile, error) {
	rootPath, err := filepath.Abs(opts.RootPath)
	if err != nil {
		return nil, err
	}

	// Ecosystem-linked install/build dirs (node_modules, .venv, venv, target,
	// build, packages, …) must not be walked for manifests: a dependency bundled
	// inside one can ship a foreign manifest (e.g. a package.json inside a pypi
	// package's site-packages), which would otherwise be mis-attributed to the
	// wrong ecosystem. ecosystems.Resolve is the single source of truth and
	// already manifest-gates the ambiguous shared dirs (vendor/target/build/
	// packages), so a legitimately-named build/ in an unrelated project is not
	// over-pruned. Installed-dir discovery reads these dirs directly, not via this
	// walker, so pruning them here loses no real packages.
	pruneDirs := make(map[string]bool)
	for _, t := range ecosystems.Resolve(rootPath, false) {
		pruneDirs[t.Path] = true
	}

	var gitignore *ignore.Matcher
	if opts.RespectGitignore {
		gitignore = ignore.New()
		gitignore.LoadDir(rootPath, "")
	}

	var detected []DetectedFile

	err = filepath.WalkDir(rootPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible paths
		}

		// Calculate relative path and depth
		relPath, _ := filepath.Rel(rootPath, path)
		if relPath == "." {
			relPath = ""
		}

		depth := 0
		if relPath != "" {
			depth = strings.Count(relPath, string(filepath.Separator)) + 1
		}

		// Skip directories beyond max depth
		if d.IsDir() {
			if relPath != "" && depth > opts.MaxDepth {
				return filepath.SkipDir
			}

			// Skip common non-useful directories
			base := d.Name()
			if base == "node_modules" || base == ".git" || base == ".hg" ||
				base == "__pycache__" || base == ".tox" || base == ".venv" ||
				base == "vendor" || base == ".cargo" || base == ".vulnetix" {
				return filepath.SkipDir
			}

			// Skip resolved ecosystem install/build dirs (venv, env, target,
			// build, packages, .yarn/cache, …) so bundled foreign manifests are
			// never picked up. Matched by absolute path so nested specs (e.g.
			// .yarn/cache) and manifest-gated dirs resolve correctly.
			if pruneDirs[path] {
				return filepath.SkipDir
			}

			// Check excludes on directories
			if shouldExclude(relPath, opts.Excludes) {
				return filepath.SkipDir
			}

			// Honour .gitignore (accumulate this dir's rules first so its
			// children are evaluated against them).
			if gitignore != nil {
				if relPath != "" && gitignore.Ignored(relPath, true) {
					return filepath.SkipDir
				}
				gitignore.LoadDir(path, relPath)
			}

			return nil
		}

		// Files beyond max depth are skipped
		if depth > opts.MaxDepth {
			return nil
		}

		// Check excludes
		if shouldExclude(relPath, opts.Excludes) {
			return nil
		}

		if gitignore != nil && gitignore.Ignored(relPath, false) {
			return nil
		}

		displayPath := "./" + relPath
		if relPath == "" {
			displayPath = "./" + d.Name()
		}

		// Check if it's a known manifest
		if info, ok := DetectManifest(path); ok {
			supported := SupportedManifestTypes[info.Type]
			detected = append(detected, DetectedFile{
				Path:         path,
				RelPath:      displayPath,
				FileType:     FileTypeManifest,
				ManifestInfo: info,
				Supported:    supported,
			})
			return nil
		}

		// Check if it's an SBOM document (only .json files)
		if strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			fileType, version, supported := DetectSBOM(path)
			if fileType != FileTypeUnknown {
				detected = append(detected, DetectedFile{
					Path:        path,
					RelPath:     displayPath,
					FileType:    fileType,
					SBOMVersion: version,
					Supported:   supported,
				})
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return detected, nil
}

// shouldExclude checks whether a relative path matches any of the exclusion globs.
func shouldExclude(relPath string, excludes []string) bool {
	for _, pattern := range excludes {
		if matched, _ := filepath.Match(pattern, relPath); matched {
			return true
		}
		// Also match against the base name
		if matched, _ := filepath.Match(pattern, filepath.Base(relPath)); matched {
			return true
		}
	}
	return false
}
