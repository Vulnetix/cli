package sast

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/vulnetix/cli/v3/internal/ignore"
	"github.com/vulnetix/cli/v3/internal/secretscan"
)

// ScanInput is serialized to JSON and passed as the OPA input document.
type ScanInput struct {
	// FileSet maps each relative file path to true for O(1) existence checks in Rego.
	FileSet map[string]bool `json:"file_set"`
	// DirsByLanguage maps language name to directories containing that language's indicator files.
	DirsByLanguage map[string][]string `json:"dirs_by_language"`
	// FileContents maps relative path to file text. Populated lazily for small files
	// when content-level rules are present. Files over MaxFileSize and binary files are
	// skipped unless binary inspection is enabled (see FileScanOptions).
	FileContents map[string]string `json:"file_contents,omitempty"`
	// ScanRoot is the absolute path being scanned (for display; rules use relative paths).
	ScanRoot string `json:"scan_root"`
}

// languageIndicators maps language names to files whose presence indicates that language.
var languageIndicators = map[string][]string{
	"go":     {"go.mod"},
	"python": {"pyproject.toml", "requirements.txt", "Pipfile", "setup.py"},
	"node":   {"package.json"},
	"rust":   {"Cargo.toml"},
	"ruby":   {"Gemfile"},
	"java":   {"pom.xml", "build.gradle", "build.gradle.kts"},
	"php":    {"composer.json"},
	"dotnet": {"*.csproj", "*.sln"},
}

// skipDirs is the set of directories we always skip during a regular scan
// walker. .git is intentionally NOT in this list — the secrets subcommand
// walks the .git directory by default (honouring --ignore-git) and we want
// a single walker to handle both cases.
var skipDirs = map[string]bool{
	"node_modules": true,
	".hg":          true,
	"__pycache__":  true,
	".tox":         true,
	".venv":        true,
	"vendor":       true,
	".cargo":       true,
	".vulnetix":    true,
}

// BuildScanInput walks the filesystem at rootPath and builds the OPA input document.
func BuildScanInput(rootPath string, maxDepth int, excludes []string) (*ScanInput, error) {
	return BuildScanInputWithOptions(rootPath, BuildOptions{
		MaxDepth: maxDepth,
		Excludes: excludes,
	})
}

// BuildOptions controls how the filesystem is walked and how binary/git
// content is folded into the scan input. Zero-value options produce the
// legacy behaviour: text files only, no git history.
type BuildOptions struct {
	MaxDepth int
	Excludes []string

	// IgnoreGit, when true, skips the .git directory entirely. The default
	// is false: the secrets subcommand walks .git to surface credentials
	// that exist only in past commits.
	IgnoreGit bool

	// IgnoreGlobs is an additional set of glob patterns to exclude. The
	// patterns are matched against the relative path and the base name
	// (mirroring --exclude). The CLI's --ignore flag is wired into this
	// slice so that a single --ignore "fixtures/**" is enough.
	IgnoreGlobs []string

	// IgnoreBinaries, when true, skips binary files entirely. When false
	// (the default for the secrets subcommand), binary files are inspected
	// with strings + EXIF and the result is added to FileContents.
	IgnoreBinaries bool

	// GitHistory, when true, walks the git history at rootPath and adds
	// each file version to FileContents under the __git_history__/ prefix.
	// Requires that IgnoreGit be false; if both are set, IgnoreGit wins.
	GitHistory bool

	// GitHistoryMaxCommits caps the number of commits walked.
	GitHistoryMaxCommits int
	// GitHistoryMaxFiles caps the number of file versions emitted.
	GitHistoryMaxFiles int

	// RespectGitignore, when true, prunes files and directories matched by
	// .gitignore files. Defaults false for backwards compatibility; the
	// sast/secrets/containers/iac/cbom/aibom commands set it true unless the
	// user passes their --*-include-ignored override.
	RespectGitignore bool
}

// BuildScanInputWithOptions is the full-control entry point. It replaces
// BuildScanInput when the caller needs to enable binary or git-history
// inspection (the secrets subcommand does, the generic scan does not).
func BuildScanInputWithOptions(rootPath string, opts BuildOptions) (*ScanInput, error) {
	absRoot, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, err
	}

	input := &ScanInput{
		FileSet:        make(map[string]bool),
		DirsByLanguage: make(map[string][]string),
		ScanRoot:       absRoot,
	}

	// Track which dirs contain which indicator files.
	dirIndicators := make(map[string]map[string]bool) // dir → set of indicator basenames

	// combinedExcludes merges legacy --exclude with --ignore so that
	// glob matching is performed identically for both.
	combinedExcludes := make([]string, 0, len(opts.Excludes)+len(opts.IgnoreGlobs))
	combinedExcludes = append(combinedExcludes, opts.Excludes...)
	combinedExcludes = append(combinedExcludes, opts.IgnoreGlobs...)

	var gitignore *ignore.Matcher
	if opts.RespectGitignore {
		gitignore = ignore.New()
		gitignore.LoadDir(absRoot, "")
	}

	err = filepath.WalkDir(absRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		relPath, _ := filepath.Rel(absRoot, path)
		if relPath == "." {
			relPath = ""
		}
		// Normalize to forward slashes for Rego compatibility.
		relPath = filepath.ToSlash(relPath)

		depth := 0
		if relPath != "" {
			depth = strings.Count(relPath, "/") + 1
		}

		if d.IsDir() {
			if relPath != "" && depth > opts.MaxDepth {
				return filepath.SkipDir
			}
			// .git is special: by default we walk into it (the secrets
			// subcommand scans the whole .git directory), but --ignore-git
			// and --ignore ".git" both suppress it.
			base := d.Name()
			if base == ".git" {
				if opts.IgnoreGit {
					return filepath.SkipDir
				}
				if shouldExclude(relPath, combinedExcludes) || shouldExclude(".git", combinedExcludes) {
					return filepath.SkipDir
				}
				// Recurse normally so loose objects and refs get walked.
				return nil
			}
			if skipDirs[base] {
				return filepath.SkipDir
			}
			if shouldExclude(relPath, combinedExcludes) {
				return filepath.SkipDir
			}
			if gitignore != nil {
				if relPath != "" && gitignore.Ignored(relPath, true) {
					return filepath.SkipDir
				}
				gitignore.LoadDir(path, relPath)
			}
			return nil
		}

		if depth > opts.MaxDepth {
			return nil
		}
		if shouldExclude(relPath, combinedExcludes) {
			return nil
		}
		if gitignore != nil && gitignore.Ignored(relPath, false) {
			return nil
		}

		// Add to file set.
		if relPath == "" {
			relPath = d.Name()
		}
		input.FileSet[relPath] = true

		// Track indicator files for language detection.
		dir := filepath.ToSlash(filepath.Dir(relPath))
		if dir == "." {
			dir = "."
		}
		baseName := d.Name()
		if dirIndicators[dir] == nil {
			dirIndicators[dir] = make(map[string]bool)
		}
		dirIndicators[dir][baseName] = true

		return nil
	})
	if err != nil {
		return nil, err
	}

	// Build dirs_by_language from collected indicators.
	for dir, indicators := range dirIndicators {
		for lang, patterns := range languageIndicators {
			for _, pattern := range patterns {
				if matchesIndicator(indicators, pattern) {
					input.DirsByLanguage[lang] = append(input.DirsByLanguage[lang], dir)
					break
				}
			}
		}
	}

	return input, nil
}

// matchesIndicator checks if any file in the set matches the indicator pattern.
// Supports exact names and glob patterns (e.g. "*.csproj").
func matchesIndicator(files map[string]bool, pattern string) bool {
	if strings.ContainsAny(pattern, "*?") {
		for name := range files {
			if matched, _ := filepath.Match(pattern, name); matched {
				return true
			}
		}
		return false
	}
	return files[pattern]
}

// shouldExclude checks if a path matches any exclude glob pattern.
func shouldExclude(relPath string, excludes []string) bool {
	for _, pattern := range excludes {
		if matched, _ := filepath.Match(pattern, relPath); matched {
			return true
		}
		base := filepath.Base(relPath)
		if matched, _ := filepath.Match(pattern, base); matched {
			return true
		}
	}
	return false
}

// LoadOptions configures LoadFileContents. The MaxFileSize and IgnoreBinaries
// fields correspond directly to the CLI flags of the same name; MaxDepth and
// Excludes are not relevant here (the walker has already determined the set
// of files to consider).
type LoadOptions struct {
	// MaxFileSize is the upper bound for any single file's text content
	// (raw or extracted). Files larger than this are skipped entirely.
	MaxFileSize int64
	// IgnoreBinaries, when true, skips binary files. When false (the
	// default for the secrets subcommand), binary files are inspected:
	// printable strings are extracted with the secretscan package and any
	// EXIF/IPTC/XMP metadata is added under __exif__/.
	IgnoreBinaries bool
	// MinStringLength is the minimum run length to surface when extracting
	// strings from binaries. Defaults to secretscan.StringMin (4).
	MinStringLength int
}

// LoadFileContents populates input.FileContents for files matching the given
// language extensions. Files over maxSize bytes and binary files are skipped.
//
// When LoadOptions is provided the caller can opt into binary inspection
// (strings + EXIF) and the synthetic content is folded into the same map.
func LoadFileContents(input *ScanInput, maxSize int64) {
	LoadFileContentsWithOptions(input, LoadOptions{MaxFileSize: maxSize})
}

// LoadFileContentsWithOptions is the full-control variant used by the
// secrets subcommand.
func LoadFileContentsWithOptions(input *ScanInput, opts LoadOptions) {
	if input.FileContents == nil {
		input.FileContents = make(map[string]string)
	}
	for relPath := range input.FileSet {
		absPath := filepath.Join(input.ScanRoot, filepath.FromSlash(relPath))
		info, err := os.Stat(absPath)
		if err != nil || info.Size() == 0 {
			continue
		}
		if opts.MaxFileSize > 0 && info.Size() > opts.MaxFileSize {
			continue
		}
		data, err := os.ReadFile(absPath)
		if err != nil {
			continue
		}
		// Synthetic paths for non-text content must never overwrite a real
		// file's content. The walker only emits real paths; only the
		// binary-inspection / git-history paths below use prefixes.
		if isBinary := looksBinary(data); isBinary {
			if opts.IgnoreBinaries {
				continue
			}
			// Inspect binary: strings + EXIF.
			insight := secretscan.InspectBinary(relPath, data, secretscan.InspectOptions{
				IncludeStrings:  true,
				MinStringLength: opts.MinStringLength,
			})
			if insight.StringsKey != "" && insight.StringsVal != "" {
				input.FileContents[insight.StringsKey] = insight.StringsVal
			}
			if insight.EXIFKey != "" {
				input.FileContents[insight.EXIFKey] = insight.EXIFVal
			}
			continue
		}
		input.FileContents[relPath] = string(data)
	}
}

// looksBinary is a small probe that decides whether a file should be treated
// as opaque. A single NUL byte in the first 512 bytes is the strongest
// signal that the file is not text.
func looksBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	check := data
	if len(check) > 512 {
		check = check[:512]
	}
	for _, b := range check {
		if b == 0 {
			return true
		}
	}
	return false
}

// MergeGitHistoryEntries injects the file versions returned by
// secretscan.ScanGitHistory into input.FileContents. Returns the number of
// entries injected. Duplicate keys (same commit, same path) are silently
// ignored.
func MergeGitHistoryEntries(input *ScanInput, entries []secretscan.GitHistoryEntry) int {
	if input.FileContents == nil {
		input.FileContents = make(map[string]string)
	}
	n := 0
	for _, e := range entries {
		if e.Key == "" {
			continue
		}
		if _, exists := input.FileContents[e.Key]; exists {
			continue
		}
		input.FileContents[e.Key] = e.Value
		n++
	}
	return n
}
