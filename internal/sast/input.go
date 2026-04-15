package sast

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// ScanInput is serialized to JSON and passed as the OPA input document.
type ScanInput struct {
	// FileSet maps each relative file path to true for O(1) existence checks in Rego.
	FileSet map[string]bool `json:"file_set"`
	// DirsByLanguage maps language name to directories containing that language's indicator files.
	DirsByLanguage map[string][]string `json:"dirs_by_language"`
	// FileContents maps relative path to file text. Populated lazily for small files
	// when content-level rules are present. Files over 1MB and binary files are skipped.
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

// skipDirs are directories that should never be walked.
var skipDirs = map[string]bool{
	"node_modules": true,
	".git":         true,
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
			if relPath != "" && depth > maxDepth {
				return filepath.SkipDir
			}
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			if shouldExclude(relPath, excludes) {
				return filepath.SkipDir
			}
			return nil
		}

		if depth > maxDepth {
			return nil
		}
		if shouldExclude(relPath, excludes) {
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

// LoadFileContents populates input.FileContents for files matching the given
// language extensions. Files over maxSize bytes and binary files are skipped.
func LoadFileContents(input *ScanInput, maxSize int64) {
	if input.FileContents == nil {
		input.FileContents = make(map[string]string)
	}
	for relPath := range input.FileSet {
		absPath := filepath.Join(input.ScanRoot, filepath.FromSlash(relPath))
		info, err := os.Stat(absPath)
		if err != nil || info.Size() > maxSize || info.Size() == 0 {
			continue
		}
		data, err := os.ReadFile(absPath)
		if err != nil {
			continue
		}
		// Skip binary files (check for null bytes in first 512 bytes).
		check := data
		if len(check) > 512 {
			check = check[:512]
		}
		if slices.Contains(check, 0) {
			continue
		}
		input.FileContents[relPath] = string(data)
	}
}
