package scan

import (
	"os"
	"path/filepath"
	"strings"
)

// WalkOptions configures the filesystem walk behavior.
type WalkOptions struct {
	RootPath string
	MaxDepth int
	Excludes []string // glob patterns to exclude
}

// WalkForScanFiles walks the filesystem from root, up to maxDepth, looking for
// manifest files and potential SBOM documents.
func WalkForScanFiles(opts WalkOptions) ([]DetectedFile, error) {
	rootPath, err := filepath.Abs(opts.RootPath)
	if err != nil {
		return nil, err
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
				base == "vendor" || base == ".cargo" {
				return filepath.SkipDir
			}

			// Check excludes on directories
			if shouldExclude(relPath, opts.Excludes) {
				return filepath.SkipDir
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
