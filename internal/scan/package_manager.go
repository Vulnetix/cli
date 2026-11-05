package scan

import (
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// A package-manager scope narrows `vulnetix sca` to the manifests of some package
// managers, so a repository can run one job per manager. Every detected file has
// at most one manager, so legs never overlap; `--not-package-manager` naming the
// other legs' managers picks up the rest, which includes committed SBOMs and the
// packages named in CI pipelines and shell scripts.

// managerByType maps a manifest type to its manager, for types only one manager
// reads. package.json and pyproject.toml are read by several: lockManagers
// decides those.
var managerByType = map[string]string{
	"package-lock.json": "npm", "yarn.lock": "yarn", "pnpm-lock.yaml": "pnpm",
	"bun.lock": "bun", "bun.lockb": "bun",
	"requirements.txt": "pip", "requirements.in": "pip", "setup.py": "pip", "setup.cfg": "pip", "pylock.toml": "pip",
	"Pipfile": "pipenv", "Pipfile.lock": "pipenv", "poetry.lock": "poetry", "uv.lock": "uv",
	"go.mod": "go", "go.sum": "go",
	"Cargo.toml": "cargo", "Cargo.lock": "cargo",
	"Gemfile": "bundler", "Gemfile.lock": "bundler",
	"pom.xml": "maven",
	"build.gradle": "gradle", "build.gradle.kts": "gradle", "gradle.lockfile": "gradle",
	"composer.json": "composer", "composer.lock": "composer",
	"packages.lock.json": "nuget", "packages.config": "nuget", "paket.dependencies": "nuget",
	"paket.lock": "nuget", "Directory.Packages.props": "nuget", "*.csproj": "nuget",
	"pubspec.yaml": "pub", "pubspec.lock": "pub",
	"mix.exs": "hex", "mix.lock": "hex",
	"Podfile": "cocoapods", "Podfile.lock": "cocoapods",
	"Package.swift": "swift", "Package.resolved": "swift",
}

// lockManagers lists, for a manifest several managers read, the lock file naming
// each one, and the manager that applies with no lock file.
var lockManagers = map[string]struct {
	locks    [][2]string
	fallback string
}{
	"package.json": {[][2]string{
		{"yarn.lock", "yarn"}, {"pnpm-lock.yaml", "pnpm"}, {"bun.lock", "bun"}, {"bun.lockb", "bun"},
		{"package-lock.json", "npm"}, {"npm-shrinkwrap.json", "npm"},
	}, "npm"},
	"pyproject.toml": {[][2]string{{"uv.lock", "uv"}, {"poetry.lock", "poetry"}, {"Pipfile.lock", "pipenv"}}, "pip"},
}

// PackageManagers lists the names --package-manager accepts.
func PackageManagers() []string {
	seen := map[string]bool{}
	for _, m := range managerByType {
		seen[m] = true
	}
	out := make([]string, 0, len(seen))
	for m := range seen {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// PackageManagerOf returns the manager that owns f, or "" when none does. A
// workspace member's package.json is governed by the lock file at the workspace
// root, so a shared manifest looks up through its parent directories.
func PackageManagerOf(f DetectedFile, present map[string]bool) string {
	if f.ManifestInfo == nil {
		return ""
	}
	if m, ok := managerByType[f.ManifestInfo.Type]; ok {
		return m
	}
	shared, ok := lockManagers[f.ManifestInfo.Type]
	if !ok {
		return ""
	}
	dir := path.Dir(filepath.ToSlash(f.RelPath))
	for {
		for _, l := range shared.locks {
			if present[path.Join(dir, l[0])] {
				return l[1]
			}
		}
		if dir == "." || dir == "/" {
			return shared.fallback
		}
		dir = path.Dir(dir)
	}
}

// ManagerScope is a resolved --package-manager / --not-package-manager pair. The
// zero value scopes nothing.
type ManagerScope struct {
	Only, Not []string
}

// NewManagerScope validates the flags.
func NewManagerScope(only, not []string) (ManagerScope, error) {
	if len(only) > 0 && len(not) > 0 {
		return ManagerScope{}, fmt.Errorf("--package-manager and --not-package-manager cannot be combined")
	}
	known := PackageManagers()
	resolve := func(flag string, names []string) ([]string, error) {
		var out []string
		for _, n := range names {
			m := strings.ToLower(strings.TrimSpace(n))
			if !slices.Contains(known, m) {
				return nil, fmt.Errorf("%s: unknown package manager %q (want one of %s)", flag, n, strings.Join(known, ", "))
			}
			if !slices.Contains(out, m) {
				out = append(out, m)
			}
		}
		sort.Strings(out)
		return out, nil
	}
	o, err := resolve("--package-manager", only)
	if err != nil {
		return ManagerScope{}, err
	}
	n, err := resolve("--not-package-manager", not)
	if err != nil {
		return ManagerScope{}, err
	}
	return ManagerScope{Only: o, Not: n}, nil
}

// Active reports whether the scope narrows anything.
func (s ManagerScope) Active() bool { return len(s.Only) > 0 || len(s.Not) > 0 }

// Filter keeps the files of this leg.
func (s ManagerScope) Filter(files []DetectedFile) []DetectedFile {
	if !s.Active() {
		return files
	}
	present := make(map[string]bool, len(files))
	for _, f := range files {
		present[path.Clean(filepath.ToSlash(f.RelPath))] = true
	}
	kept := make([]DetectedFile, 0, len(files))
	for _, f := range files {
		owner := PackageManagerOf(f, present)
		if len(s.Only) > 0 && slices.Contains(s.Only, owner) ||
			len(s.Not) > 0 && !slices.Contains(s.Not, owner) {
			kept = append(kept, f)
		}
	}
	return kept
}
