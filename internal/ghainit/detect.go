package ghainit

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vulnetix/cli/v4/internal/sast"
	"github.com/vulnetix/cli/v4/internal/scan"
)

// A language counts at 10 or more files and 2% or more of the source: a handful
// of helper scripts should not add a job. Its findings still land in the rest step.
const (
	minLanguageFiles   = 10
	minLanguagePercent = 2
)

// granularLimit is the most languages or managers that get a job each. A
// repository with more uses the high-level scanner.
const granularLimit = 2

// Signals is what a repository is made of.
type Signals struct {
	Languages  []string // largest first
	Managers   []string // largest first
	Terraform  bool
	Containers bool
}

var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, ".venv": true, "venv": true,
	"dist": true, "build": true, "target": true, ".vulnetix": true, "__pycache__": true, ".terraform": true}

// Detect walks root.
func Detect(root string) (*Signals, error) {
	langFiles := map[string]int{}
	total := 0
	var detected []scan.DetectedFile
	sig := &Signals{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if strings.HasSuffix(d.Name(), ".tf") {
			sig.Terraform = true
		}
		lower := strings.ToLower(d.Name())
		if lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile.") || lower == "containerfile" {
			sig.Containers = true
		}
		if l := sast.OwnerLanguage(rel); l != "" && sourceLanguage[l] {
			langFiles[l]++
			total++
		}
		if info, ok := scan.DetectManifest(rel); ok {
			detected = append(detected, scan.DetectedFile{RelPath: rel, FileType: scan.FileTypeManifest, ManifestInfo: info})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for l, n := range langFiles {
		if n >= minLanguageFiles && n*100 >= total*minLanguagePercent {
			sig.Languages = append(sig.Languages, l)
		}
	}
	sortBy(sig.Languages, langFiles)
	present := map[string]bool{}
	for _, f := range detected {
		present[filepath.ToSlash(f.RelPath)] = true
	}
	managers := map[string]int{}
	for _, f := range detected {
		if m := scan.PackageManagerOf(f, present); m != "" {
			managers[m]++
		}
	}
	for m := range managers {
		sig.Managers = append(sig.Managers, m)
	}
	sortBy(sig.Managers, managers)
	return sig, nil
}

// sourceLanguage is what has a sast action. Terraform and Docker are their own
// scanners; markup and query languages live in the rest step.
var sourceLanguage = map[string]bool{"python": true, "java": true, "javascript": true, "c-cpp": true, "go": true,
	"php": true, "ruby": true, "kotlin": true, "csharp": true, "shell": true, "rust": true}

func sortBy(names []string, weight map[string]int) {
	sort.Slice(names, func(i, j int) bool {
		if weight[names[i]] != weight[names[j]] {
			return weight[names[i]] > weight[names[j]]
		}
		return names[i] < names[j]
	})
}
