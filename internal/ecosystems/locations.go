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
	"strings"
)

// Target is one resolved scan location handed to the malscan engine.
type Target struct {
	Ecosystem  string // human ecosystem label, e.g. "javascript", "python"
	EngineSlug string // malscan-engine feed slug: npm|pypi|go|cargo|rubygems|nuget|homebrew|generic
	Path       string // absolute path that exists on disk
	UserScoped bool   // true when sourced from a home/user cache (gated by --include-home)
	// SystemScoped is true when the location came from --include-system: a
	// machine-wide install dir, or a cache in another account's home.
	SystemScoped bool
	Label        string // short human label for output, e.g. "node_modules" or "~/.cargo/registry"
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
	// userDirs returns absolute home/user cache paths. getenv answers the
	// overrides (GOMODCACHE, CARGO_HOME, …); it is os.Getenv for the invoking
	// user and blank for every other account, whose environment we cannot see.
	// Called only when --include-home or --include-system is set.
	userDirs func(home string, getenv func(string) string) []string
	// systemDirs are machine-wide install locations, as globs relative to the
	// system root: where the distro's own packages, `sudo pip install` and
	// `npm install -g` put things. Called only when --include-system is set.
	systemDirs []string
}

// table is the maintainable catalog of ecosystem locations. Add a new ecosystem
// here and both the subcommand and the scan/sca hook pick it up.
var table = []ecosystem{
	{
		name:       "javascript",
		engineSlug: "npm",
		systemDirs: []string{
			"usr/lib/node_modules",
			"usr/local/lib/node_modules",
			"usr/share/nodejs",
			"opt/homebrew/lib/node_modules",
		},
		projectDirs: []dirSpec{
			{glob: "node_modules"},
			{glob: ".yarn/cache"},
			{glob: ".yarn/unplugged"},
			{glob: ".pnpm-store"},
		},
		userDirs: func(home string, getenv func(string) string) []string {
			var out []string
			if c := getenv("npm_config_cache"); c != "" {
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
		systemDirs: []string{
			"usr/lib/python3*/site-packages",
			"usr/lib/python3*/dist-packages",
			"usr/lib/python3/dist-packages",
			"usr/lib64/python3*/site-packages",
			"usr/local/lib/python3*/site-packages",
			"usr/local/lib/python3*/dist-packages",
			"opt/homebrew/lib/python3*/site-packages",
			"Library/Frameworks/Python.framework/Versions/*/lib/python3*/site-packages",
		},
		projectDirs: []dirSpec{
			{glob: ".venv"},
			{glob: "venv"},
			{glob: "env"},
			{glob: ".tox"},
			{glob: "__pypackages__"},
		},
		userDirs: func(home string, getenv func(string) string) []string {
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
		name:       "conda",
		engineSlug: "pypi",
		systemDirs: []string{
			"opt/conda/pkgs",
			"opt/miniconda3/pkgs",
			"opt/anaconda3/pkgs",
		},
		projectDirs: []dirSpec{
			{glob: "envs", requireManifest: []string{"environment.yml", "environment.yaml"}},
			{glob: ".conda", requireManifest: []string{"environment.yml", "environment.yaml"}},
		},
		userDirs: func(home string, getenv func(string) string) []string {
			var out []string
			for _, d := range []string{"miniconda3", "anaconda3", ".conda"} {
				p := filepath.Join(home, d, "pkgs")
				if _, err := os.Stat(p); err == nil {
					out = append(out, p)
				}
			}
			return out
		},
	},
	{
		name:       "go",
		engineSlug: "go",
		systemDirs: []string{
			"usr/local/go/pkg/mod",
		},
		projectDirs: []dirSpec{
			{glob: "vendor", requireManifest: []string{"go.mod"}},
		},
		userDirs: func(home string, getenv func(string) string) []string {
			if mc := getenv("GOMODCACHE"); mc != "" {
				return []string{mc}
			}
			if gp := getenv("GOPATH"); gp != "" {
				return []string{filepath.Join(gp, "pkg", "mod")}
			}
			return []string{filepath.Join(home, "go", "pkg", "mod")}
		},
	},
	{
		name:       "rust",
		engineSlug: "cargo",
		systemDirs: []string{
			"usr/local/cargo/registry",
			"usr/local/cargo/git",
		},
		projectDirs: []dirSpec{
			{glob: "vendor", requireManifest: []string{"Cargo.toml"}},
			{glob: "target", requireManifest: []string{"Cargo.toml"}},
		},
		userDirs: func(home string, getenv func(string) string) []string {
			base := getenv("CARGO_HOME")
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
		systemDirs: []string{
			"var/lib/gems/*",
			"usr/share/gems",
			"usr/lib/ruby/gems/*",
			"usr/lib64/ruby/gems/*",
			"usr/local/lib/ruby/gems/*",
			"usr/local/bundle",
		},
		projectDirs: []dirSpec{
			{glob: "vendor/bundle"},
			{glob: ".bundle"},
		},
		userDirs: func(home string, getenv func(string) string) []string {
			if gh := getenv("GEM_HOME"); gh != "" {
				return []string{gh}
			}
			return []string{filepath.Join(home, ".gem")}
		},
	},
	{
		name:       "php",
		engineSlug: "generic",
		systemDirs: []string{
			"usr/share/php",
			"usr/local/share/composer/vendor",
		},
		projectDirs: []dirSpec{
			{glob: "vendor", requireManifest: []string{"composer.json"}},
		},
		userDirs: func(home string, getenv func(string) string) []string {
			return []string{
				filepath.Join(home, ".composer"),
				filepath.Join(home, ".config", "composer"),
			}
		},
	},
	{
		name:       "java",
		engineSlug: "generic",
		systemDirs: []string{
			"usr/share/java",
			"usr/share/maven-repo",
		},
		projectDirs: []dirSpec{
			{glob: "target", requireManifest: []string{"pom.xml"}},
			{glob: "build", requireManifest: []string{"build.gradle", "build.gradle.kts"}},
		},
		userDirs: func(home string, getenv func(string) string) []string {
			return []string{
				filepath.Join(home, ".m2", "repository"),
				filepath.Join(home, ".gradle", "caches"),
			}
		},
	},
	{
		name:       "dotnet",
		engineSlug: "nuget",
		systemDirs: []string{
			"usr/share/dotnet/sdk/NuGetFallbackFolder",
		},
		projectDirs: []dirSpec{
			{glob: "packages", requireManifest: []string{"*.sln", "*.csproj", "packages.config"}},
		},
		userDirs: func(home string, getenv func(string) string) []string {
			if p := getenv("NUGET_PACKAGES"); p != "" {
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
		userDirs: func(home string, getenv func(string) string) []string {
			if p := getenv("PUB_CACHE"); p != "" {
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
		userDirs: func(home string, getenv func(string) string) []string {
			return []string{
				filepath.Join(home, ".hex"),
				filepath.Join(home, ".mix"),
			}
		},
	},
}

// Scope says which locations beyond the project a resolution covers.
type Scope struct {
	// Home adds the invoking user's caches (~/.npm, ~/go/pkg/mod, …).
	Home bool
	// System adds machine-wide install dirs under SystemRoot and the caches in
	// every account's home there, so the answer is the whole host rather than
	// one person's checkout.
	System bool
	// SystemRoot is the filesystem --include-system describes. Blank means "/";
	// a mounted volume, an unpacked image or /proc/<pid>/root describes that
	// system instead of the one the CLI is running on.
	SystemRoot string
}

// Resolve returns every dependency install/cache location that exists for the
// given scan root. Project-local dirs are always considered; user-scoped/home
// caches are added for scope.Home, and machine-wide dirs plus every account's
// caches for scope.System. Results are de-duplicated by absolute path (first
// ecosystem to claim a path wins), so a shared "vendor" directory is never
// scanned twice.
func Resolve(root string, scope Scope) []Target {
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

	sysRoot := SystemRoot(scope.SystemRoot)
	// The invoking user's home belongs to the system being described only when
	// that system is the live one; a mounted image has its own accounts.
	liveHome := home != "" && sysRoot == string(filepath.Separator)

	if (scope.Home || (scope.System && liveHome)) && home != "" {
		for _, eco := range table {
			if eco.userDirs == nil {
				continue
			}
			for _, d := range eco.userDirs(home, os.Getenv) {
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

	if scope.System {
		for _, eco := range table {
			for _, glob := range eco.systemDirs {
				matches, _ := filepath.Glob(filepath.Join(sysRoot, filepath.FromSlash(glob)))
				for _, m := range matches {
					add(Target{
						Ecosystem:    eco.name,
						EngineSlug:   eco.engineSlug,
						Path:         m,
						SystemScoped: true,
						Label:        systemLabel(sysRoot, m),
					})
				}
			}
		}
		noEnv := func(string) string { return "" }
		for _, h := range SystemHomes(sysRoot) {
			for _, eco := range table {
				if eco.userDirs == nil {
					continue
				}
				for _, d := range eco.userDirs(h, noEnv) {
					add(Target{
						Ecosystem:    eco.name,
						EngineSlug:   eco.engineSlug,
						Path:         d,
						UserScoped:   true,
						SystemScoped: true,
						Label:        systemLabel(sysRoot, d),
					})
				}
			}
		}
	}

	return out
}

// SystemRoot normalises a --system-root value: blank is the live root.
func SystemRoot(root string) string {
	if root == "" {
		return string(filepath.Separator)
	}
	if abs, err := filepath.Abs(root); err == nil {
		return abs
	}
	return root
}

// SystemHomes lists the account home directories under a system root: every
// directory in /home (and /Users on macOS images), plus /root. Service
// accounts with homes elsewhere (/var/lib/jenkins) are reached through the
// system dirs or not at all; reading /etc/passwd would trust a file the
// scanned system controls to point the walk anywhere.
func SystemHomes(sysRoot string) []string {
	var out []string
	for _, parent := range []string{"home", "Users"} {
		entries, err := os.ReadDir(filepath.Join(sysRoot, parent))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() && e.Name() != "Shared" && !strings.HasPrefix(e.Name(), ".") {
				out = append(out, filepath.Join(sysRoot, parent, e.Name()))
			}
		}
	}
	if isDir(filepath.Join(sysRoot, "root")) {
		out = append(out, filepath.Join(sysRoot, "root"))
	}
	return out
}

// SystemBinaryDirs are the directories a whole-system scan inspects for
// compiled artefacts. It is not the whole root: /proc, /sys and /dev are not
// files, and /usr/lib alone holds tens of thousands of shared objects that the
// OS package database already accounts for. Symlinked dirs (/bin -> usr/bin on
// merged-/usr distros) are returned once, resolved inside the system root.
func SystemBinaryDirs(sysRoot string) []string {
	var out []string
	seen := map[string]bool{}
	for _, d := range []string{"usr/bin", "usr/sbin", "usr/local/bin", "usr/local/sbin", "bin", "sbin", "usr/libexec", "usr/local/lib", "opt"} {
		p := resolveInRoot(sysRoot, filepath.Join(sysRoot, filepath.FromSlash(d)))
		if p == "" || !isDir(p) || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// resolveInRoot follows a symlinked directory the way the scanned system would:
// a relative target from its parent, an absolute one from the system root.
// filepath.EvalSymlinks would resolve an image's "/bin -> /usr/bin" on the host,
// and /proc/<pid>/root itself to the host's "/". It returns "" for a target
// that leaves the root or a chain that does not end.
func resolveInRoot(sysRoot, p string) string {
	for i := 0; i < 8; i++ {
		info, err := os.Lstat(p)
		if err != nil {
			return ""
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return p
		}
		target, err := os.Readlink(p)
		if err != nil {
			return ""
		}
		if filepath.IsAbs(target) {
			p = filepath.Join(sysRoot, target)
		} else {
			p = filepath.Join(filepath.Dir(p), target)
		}
		if rel, err := filepath.Rel(sysRoot, p); err != nil || startsWithDotDot(rel) {
			return ""
		}
	}
	return ""
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

// systemLabel renders a path under the system root as the absolute path it has
// on that system: /usr/lib/python3/dist-packages, even when the image is
// mounted at /mnt/img.
func systemLabel(sysRoot, path string) string {
	if rel, err := filepath.Rel(sysRoot, path); err == nil && !startsWithDotDot(rel) {
		return "/" + filepath.ToSlash(rel)
	}
	return path
}

func startsWithDotDot(rel string) bool {
	return len(rel) >= 2 && rel[0] == '.' && rel[1] == '.'
}
