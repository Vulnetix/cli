package filetree

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// FileTreeContext holds SCA-relevant filesystem metadata for a manifest file.
type FileTreeContext struct {
	NodeModulesTree  []string          `json:"nodeModulesTree,omitempty"`
	GitignoreContent string            `json:"gitignoreContent,omitempty"`
	LockfileMap      map[string]string `json:"lockfileMap"`
	MonorepoInfo     *MonorepoInfo     `json:"monorepoInfo,omitempty"`
	ManifestRelPath  string            `json:"manifestRelPath"`
}

// MonorepoInfo describes workspace/monorepo configuration.
type MonorepoInfo struct {
	IsMonorepo     bool     `json:"isMonorepo"`
	WorkspaceType  string   `json:"workspaceType"`
	WorkspacePaths []string `json:"workspacePaths,omitempty"`
}

const maxNodeModulesEntries = 10000
const nodeModulesMaxDepth = 2

// lockfileAssociations maps manifest filenames to their potential lockfiles.
var lockfileAssociations = map[string][]string{
	"package.json":     {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"},
	"go.mod":           {"go.sum"},
	"Cargo.toml":       {"Cargo.lock"},
	"requirements.txt": {"Pipfile.lock", "poetry.lock", "uv.lock"},
	"Pipfile":          {"Pipfile.lock"},
	"pyproject.toml":   {"poetry.lock", "uv.lock"},
	"Gemfile":          {"Gemfile.lock"},
	"composer.json":    {"composer.lock"},
	"pubspec.yaml":     {"pubspec.lock"},
}

// Collect gathers filesystem metadata for a manifest file.
// repoRoot may be empty if not in a git repo.
func Collect(manifestPath, repoRoot, ecosystem string) *FileTreeContext {
	ctx := &FileTreeContext{
		LockfileMap: make(map[string]string),
	}

	manifestDir := filepath.Dir(manifestPath)
	manifestBase := filepath.Base(manifestPath)

	// Relative path from repo root
	if repoRoot != "" {
		if rel, err := filepath.Rel(repoRoot, manifestPath); err == nil {
			ctx.ManifestRelPath = rel
		}
	}
	if ctx.ManifestRelPath == "" {
		ctx.ManifestRelPath = manifestPath
	}

	// Lockfile associations
	if candidates, ok := lockfileAssociations[manifestBase]; ok {
		for _, lock := range candidates {
			lockPath := filepath.Join(manifestDir, lock)
			if _, err := os.Stat(lockPath); err == nil {
				ctx.LockfileMap[manifestBase] = lock
				break
			}
		}
	}

	// .gitignore content (from manifest dir, then repo root)
	ctx.GitignoreContent = collectGitignore(manifestDir, repoRoot)

	// node_modules tree (npm ecosystem only)
	if ecosystem == "npm" {
		ctx.NodeModulesTree = collectNodeModulesTree(manifestDir)
	}

	// Monorepo detection
	searchDir := manifestDir
	if repoRoot != "" {
		searchDir = repoRoot
	}
	ctx.MonorepoInfo = detectMonorepo(searchDir)

	return ctx
}

func collectGitignore(manifestDir, repoRoot string) string {
	// Try manifest directory first
	content := readFileString(filepath.Join(manifestDir, ".gitignore"))
	if content != "" {
		return content
	}
	// Fall back to repo root
	if repoRoot != "" && repoRoot != manifestDir {
		return readFileString(filepath.Join(repoRoot, ".gitignore"))
	}
	return ""
}

func collectNodeModulesTree(manifestDir string) []string {
	nmPath := filepath.Join(manifestDir, "node_modules")
	info, err := os.Stat(nmPath)
	if err != nil || !info.IsDir() {
		return nil
	}

	var entries []string
	filepath.WalkDir(nmPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		if len(entries) >= maxNodeModulesEntries {
			return filepath.SkipAll
		}

		rel, _ := filepath.Rel(nmPath, path)
		if rel == "." {
			return nil
		}

		depth := strings.Count(rel, string(filepath.Separator))
		if depth >= nodeModulesMaxDepth {
			return filepath.SkipDir
		}

		entries = append(entries, rel+"/")
		return nil
	})

	return entries
}

func detectMonorepo(dir string) *MonorepoInfo {
	// npm workspaces: package.json with "workspaces" field
	pkgJSON := filepath.Join(dir, "package.json")
	if data, err := os.ReadFile(pkgJSON); err == nil {
		var pkg struct {
			Workspaces interface{} `json:"workspaces"`
		}
		if json.Unmarshal(data, &pkg) == nil && pkg.Workspaces != nil {
			paths := extractWorkspacePaths(pkg.Workspaces)
			return &MonorepoInfo{IsMonorepo: true, WorkspaceType: "npm-workspaces", WorkspacePaths: paths}
		}
	}

	// pnpm workspaces
	if _, err := os.Stat(filepath.Join(dir, "pnpm-workspace.yaml")); err == nil {
		return &MonorepoInfo{IsMonorepo: true, WorkspaceType: "pnpm-workspaces"}
	}

	// lerna
	if _, err := os.Stat(filepath.Join(dir, "lerna.json")); err == nil {
		return &MonorepoInfo{IsMonorepo: true, WorkspaceType: "lerna"}
	}

	// go workspaces
	if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
		return &MonorepoInfo{IsMonorepo: true, WorkspaceType: "go-work"}
	}

	// cargo workspace
	cargoToml := filepath.Join(dir, "Cargo.toml")
	if data, err := os.ReadFile(cargoToml); err == nil {
		if strings.Contains(string(data), "[workspace]") {
			return &MonorepoInfo{IsMonorepo: true, WorkspaceType: "cargo-workspace"}
		}
	}

	return nil
}

func extractWorkspacePaths(v interface{}) []string {
	switch w := v.(type) {
	case []interface{}:
		var paths []string
		for _, p := range w {
			if s, ok := p.(string); ok {
				paths = append(paths, s)
			}
		}
		return paths
	case map[string]interface{}:
		// npm workspaces can also be {packages: [...]}
		if pkgs, ok := w["packages"]; ok {
			return extractWorkspacePaths(pkgs)
		}
	}
	return nil
}

func readFileString(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	// Cap at 8KB to avoid bloating payload
	if len(data) > 8192 {
		data = data[:8192]
	}
	return string(data)
}
