// Package ecosystems resolves the on-disk locations where a project's
// dependencies are installed/cached, per programming-language / package-manager
// ecosystem. The malscan-engine is content-agnostic — it scans a directory tree
// it is handed — so the CLI is responsible for pointing it at the right places:
// the project-local install dirs (node_modules, .venv/site-packages, vendor, …)
// and, when asked, the user-scoped/home caches shared across all projects
// (~/.npm, ~/go/pkg/mod, ~/.cargo/registry, ~/.m2, …).
//
// The table below is the single source of truth. Each entry maps an ecosystem to
// its malscan-engine slug (used to select the right STIX IOC feed) and the dirs
// to scan. Resolve returns only the targets that actually exist on disk so the
// engine never walks phantom paths.
package ecosystems

import (
	"os"
	"path/filepath"
	"runtime"
)

// Target is one resolved scan location handed to the malscan engine.
type Target struct {
	Ecosystem  string // human ecosystem label, e.g. "javascript", "python"
	EngineSlug string // malscan-engine feed slug: npm|pypi|go|cargo|rubygems|nuget|homebrew|generic
	Path       string // absolute path that exists on disk
	UserScoped bool   // true when sourced from a home/user cache (gated by --include-home)
	Label      string // short human label for output, e.g. "node_modules" or "~/.cargo/registry"
}

// dirSpec is one project-local directory candidate (relative to the scan root).
type dirSpec struct {
	glob string // path/glob relative to root (filepath.Glob syntax)
	// requireManifest, when non-empty, gates the candidate on at least one of
	// these manifest globs existing at the scan root. Used to disambiguate the
	// shared "vendor" directory (Go vs PHP vs Rust) so we only attribute it to
	// the ecosystem whose manifest is present.
	requireManifest []string
}

// ecosystem describes one ecosystem's install/cache locations.
type ecosystem struct {
	name        string
	engineSlug  string
	projectDirs []dirSpec
	// userDirs returns absolute home/user cache paths (honoring env overrides).
	// Called only when --include-home is set.
	userDirs func(home string) []string
}

// table is the maintainable catalog of ecosystem locations. Add a new ecosystem
// here and both the subcommand and the scan/sca hook pick it up.
var table = []ecosystem{
	{
		name:       "javascript",
		engineSlug: "npm",
		projectDirs: []dirSpec{
			{glob: "node_modules"},
			{glob: ".yarn/cache"},
			{glob: ".yarn/unplugged"},
			{glob: ".pnpm-store"},
		},
		userDirs: func(home string) []string {
			var out []string
			if c := os.Getenv("npm_config_cache"); c != "" {
				out = append(out, c)
			} else {
				out = append(out, filepath.Join(home, ".npm"))
			}
			out = append(out,
				filepath.Join(home, ".bun", "install", "cache"),
				filepath.Join(home, ".local", "share", "pnpm", "store"),
				filepath.Join(home, ".pnpm-store"),
				filepath.Join(home, ".yarn", "cache"),
				filepath.Join(home, ".cache", "yarn"),
			)
			return out
		},
	},
	{
		name:       "python",
		engineSlug: "pypi",
		projectDirs: []dirSpec{
			{glob: ".venv"},
			{glob: "venv"},
			{glob: "env"},
			{glob: ".tox"},
			{glob: "__pypackages__"},
		},
		userDirs: func(home string) []string {
			out := []string{
				filepath.Join(home, ".cache", "pip"),
				filepath.Join(home, ".local", "pipx"),
			}
			// User-site for each installed minor version.
			if matches, _ := filepath.Glob(filepath.Join(home, ".local", "lib", "python*", "site-packages")); len(matches) > 0 {
				out = append(out, matches...)
			}
			if runtime.GOOS == "darwin" {
				out = append(out, filepath.Join(home, "Library", "Caches", "pip"))
			}
			return out
		},
	},
	{
		name:       "go",
		engineSlug: "go",
		projectDirs: []dirSpec{
			{glob: "vendor", requireManifest: []string{"go.mod"}},
		},
		userDirs: func(home string) []string {
			if mc := os.Getenv("GOMODCACHE"); mc != "" {
				return []string{mc}
			}
			if gp := os.Getenv("GOPATH"); gp != "" {
				return []string{filepath.Join(gp, "pkg", "mod")}
			}
			return []string{filepath.Join(home, "go", "pkg", "mod")}
		},
	},
	{
		name:       "rust",
		engineSlug: "cargo",
		projectDirs: []dirSpec{
			{glob: "vendor", requireManifest: []string{"Cargo.toml"}},
			{glob: "target", requireManifest: []string{"Cargo.toml"}},
		},
		userDirs: func(home string) []string {
			base := os.Getenv("CARGO_HOME")
			if base == "" {
				base = filepath.Join(home, ".cargo")
			}
			return []string{
				filepath.Join(base, "registry"),
				filepath.Join(base, "git"),
			}
		},
	},
	{
		name:       "ruby",
		engineSlug: "rubygems",
		projectDirs: []dirSpec{
			{glob: "vendor/bundle"},
			{glob: ".bundle"},
		},
		userDirs: func(home string) []string {
			if gh := os.Getenv("GEM_HOME"); gh != "" {
				return []string{gh}
			}
			return []string{filepath.Join(home, ".gem")}
		},
	},
	{
		name:       "php",
		engineSlug: "generic",
		projectDirs: []dirSpec{
			{glob: "vendor", requireManifest: []string{"composer.json"}},
		},
		userDirs: func(home string) []string {
			return []string{
				filepath.Join(home, ".composer"),
				filepath.Join(home, ".config", "composer"),
			}
		},
	},
	{
		name:       "java",
		engineSlug: "generic",
		projectDirs: []dirSpec{
			{glob: "target", requireManifest: []string{"pom.xml"}},
			{glob: "build", requireManifest: []string{"build.gradle", "build.gradle.kts"}},
		},
		userDirs: func(home string) []string {
			return []string{
				filepath.Join(home, ".m2", "repository"),
				filepath.Join(home, ".gradle", "caches"),
			}
		},
	},
	{
		name:       "dotnet",
		engineSlug: "nuget",
		projectDirs: []dirSpec{
			{glob: "packages", requireManifest: []string{"*.sln", "*.csproj", "packages.config"}},
		},
		userDirs: func(home string) []string {
			if p := os.Getenv("NUGET_PACKAGES"); p != "" {
				return []string{p}
			}
			return []string{filepath.Join(home, ".nuget", "packages")}
		},
	},
	{
		name:       "dart",
		engineSlug: "generic",
		projectDirs: []dirSpec{
			{glob: ".dart_tool"},
		},
		userDirs: func(home string) []string {
			if p := os.Getenv("PUB_CACHE"); p != "" {
				return []string{p}
			}
			return []string{filepath.Join(home, ".pub-cache")}
		},
	},
	{
		name:       "elixir",
		engineSlug: "generic",
		projectDirs: []dirSpec{
			{glob: "deps", requireManifest: []string{"mix.exs"}},
			{glob: "_build", requireManifest: []string{"mix.exs"}},
		},
		userDirs: func(home string) []string {
			return []string{
				filepath.Join(home, ".hex"),
				filepath.Join(home, ".mix"),
			}
		},
	},
}

// Resolve returns every dependency install/cache location that exists for the
// given scan root. Project-local dirs are always considered; user-scoped/home
// caches are added only when includeHome is true. Results are de-duplicated by
// absolute path (first ecosystem to claim a path wins), so a shared "vendor"
// directory is never scanned twice.
func Resolve(root string, includeHome bool) []Target {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		absRoot = root
	}
	home, _ := os.UserHomeDir()

	var out []Target
	seen := map[string]bool{}
	add := func(t Target) {
		abs, err := filepath.Abs(t.Path)
		if err != nil {
			abs = t.Path
		}
		if seen[abs] || !isDir(abs) {
			return
		}
		seen[abs] = true
		t.Path = abs
		out = append(out, t)
	}

	for _, eco := range table {
		for _, spec := range eco.projectDirs {
			if len(spec.requireManifest) > 0 && !anyManifestExists(absRoot, spec.requireManifest) {
				continue
			}
			matches, _ := filepath.Glob(filepath.Join(absRoot, spec.glob))
			for _, m := range matches {
				add(Target{
					Ecosystem:  eco.name,
					EngineSlug: eco.engineSlug,
					Path:       m,
					Label:      relLabel(absRoot, m),
				})
			}
		}
	}

	if includeHome && home != "" {
		for _, eco := range table {
			if eco.userDirs == nil {
				continue
			}
			for _, d := range eco.userDirs(home) {
				add(Target{
					Ecosystem:  eco.name,
					EngineSlug: eco.engineSlug,
					Path:       d,
					UserScoped: true,
					Label:      homeLabel(home, d),
				})
			}
		}
	}

	return out
}

// ScanSkipDirs is the directory-prune set the malscan engine should use for a
// dependency-tree scan. Unlike the engine's default (which prunes node_modules
// and vendor — the very dirs we are scanning), this prunes only version-control
// metadata, so nested package dirs inside node_modules/vendor ARE walked.
func ScanSkipDirs() []string {
	return []string{".git", ".hg", ".svn"}
}

// anyManifestExists reports whether any of the manifest globs resolves to an
// existing file at the scan root.
func anyManifestExists(root string, manifests []string) bool {
	for _, m := range manifests {
		matches, _ := filepath.Glob(filepath.Join(root, m))
		for _, hit := range matches {
			if info, err := os.Stat(hit); err == nil && !info.IsDir() {
				return true
			}
		}
	}
	return false
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// relLabel returns a path relative to root for display, falling back to the
// absolute path.
func relLabel(root, path string) string {
	if rel, err := filepath.Rel(root, path); err == nil {
		return rel
	}
	return path
}

// homeLabel renders a home-cache path with a leading ~ for compact output.
func homeLabel(home, path string) string {
	if rel, err := filepath.Rel(home, path); err == nil && !startsWithDotDot(rel) {
		return filepath.Join("~", rel)
	}
	return path
}

func startsWithDotDot(rel string) bool {
	return len(rel) >= 2 && rel[0] == '.' && rel[1] == '.'
}
