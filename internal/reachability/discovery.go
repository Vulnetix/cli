package reachability

import (
	"os"
	"path/filepath"
	"strings"
)

// InstallPath attempts to locate the on-disk directory for a given
// (ecosystem, package) pair starting from projectRoot. The lookup is
// purely filesystem-based: no package manager is invoked. Returns ""
// if nothing plausible is found.
//
// Each ecosystem has a canonical install layout. For monorepos or
// non-standard layouts the caller can still surface transitive matches
// even when this lookup fails.
func InstallPath(projectRoot, ecosystem, pkg string) string {
	if projectRoot == "" || pkg == "" {
		return ""
	}
	switch strings.ToLower(ecosystem) {
	case "npm", "yarn", "pnpm", "javascript", "typescript", "node":
		// Scoped names (@scope/name) are preserved verbatim.
		candidates := []string{
			filepath.Join(projectRoot, "node_modules", pkg),
		}
		// pnpm flattens scoped names: node_modules/.pnpm/<scope>+<name>@<v>/node_modules/<name>
		// Skip that variant; pnpm hoists the top-level symlink which the first
		// candidate covers.
		return firstDir(candidates)
	case "pypi", "python", "pip":
		// Walk likely venv / site-packages roots.
		candidates := []string{
			filepath.Join(projectRoot, ".venv", "lib"),
			filepath.Join(projectRoot, "venv", "lib"),
			filepath.Join(projectRoot, "env", "lib"),
		}
		for _, root := range candidates {
			hit := findPythonPackage(root, pkg)
			if hit != "" {
				return hit
			}
		}
		// Source-tree layout: src/<pkg> or <pkg>/
		if dir := firstDir([]string{
			filepath.Join(projectRoot, "src", pkg),
			filepath.Join(projectRoot, pkg),
		}); dir != "" {
			return dir
		}
	case "go", "golang":
		// Vendored modules first.
		if dir := firstDir([]string{filepath.Join(projectRoot, "vendor", pkg)}); dir != "" {
			return dir
		}
		// Module cache lookup is intentionally out of scope: GOPATH is
		// not always discoverable from a project root and version
		// resolution is non-trivial.
	case "maven", "gradle", "java":
		// Maven layout: target/dependency after `mvn dependency:copy-dependencies`
		// Gradle layout: build/dependencies/* (project-specific). Best effort.
		if dir := firstDir([]string{
			filepath.Join(projectRoot, "target", "dependency"),
			filepath.Join(projectRoot, "build", "dependencies"),
		}); dir != "" {
			return dir
		}
	case "composer", "php":
		if dir := firstDir([]string{filepath.Join(projectRoot, "vendor", pkg)}); dir != "" {
			return dir
		}
	case "gem", "rubygems", "ruby":
		if dir := firstDir([]string{filepath.Join(projectRoot, "vendor", "bundle", "ruby")}); dir != "" {
			// Vendored bundler layout; search for the specific gem.
			hit := findRubyGem(dir, pkg)
			if hit != "" {
				return hit
			}
		}
	case "cargo", "rust":
		// cargo vendor layout
		if dir := firstDir([]string{filepath.Join(projectRoot, "vendor", pkg)}); dir != "" {
			return dir
		}
	case "nuget", "c#", "csharp", "dotnet":
		// dotnet packages restore into ~/.nuget/packages typically;
		// project-local restore is rare. Skip.
	}
	return ""
}

func firstDir(candidates []string) string {
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}
	return ""
}

// findPythonPackage looks for site-packages/<pkg> beneath any
// pythonX.Y dir under libRoot.
func findPythonPackage(libRoot, pkg string) string {
	entries, err := os.ReadDir(libRoot)
	if err != nil {
		return ""
	}
	normalised := strings.ReplaceAll(pkg, "-", "_")
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "python") {
			continue
		}
		sp := filepath.Join(libRoot, e.Name(), "site-packages")
		for _, name := range []string{pkg, normalised} {
			candidate := filepath.Join(sp, name)
			if info, err := os.Stat(candidate); err == nil && info.IsDir() {
				return candidate
			}
		}
	}
	return ""
}

// findRubyGem walks vendor/bundle/ruby/<ver>/gems/<pkg>-* layouts.
func findRubyGem(root, pkg string) string {
	var found string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		name := filepath.Base(path)
		if strings.HasPrefix(name, pkg+"-") {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// skipDirs returns directory names that should be ignored during a
// transitive sweep — they aren't first-party source.
func skipDirs() map[string]struct{} {
	return map[string]struct{}{
		".git":         {},
		"node_modules": {},
		"vendor":       {},
		".venv":        {},
		"venv":         {},
		"env":          {},
		"__pycache__":  {},
		".tox":         {},
		"dist":         {},
		"build":        {},
		"target":       {},
		".gradle":      {},
		".idea":        {},
		".vscode":      {},
		".next":        {},
		".nuxt":        {},
		"coverage":     {},
		".cache":       {},
	}
}
