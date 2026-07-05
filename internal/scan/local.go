package scan

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

// Scope constants use native package manager terminology.
const (
	ScopeProduction  = "production"
	ScopeDevelopment = "development"
	ScopeTest        = "test"
	ScopePeer        = "peer"
	ScopeOptional    = "optional"
	ScopeProvided    = "provided"
	ScopeRuntime     = "runtime"
	ScopeSystem      = "system"
)

// Discovery-source provenance: how the CLI found a package. A package declared in
// a manifest is fixed by editing that manifest; a package found only in an install
// directory (e.g. a transitive in node_modules, not in any manifest) is fixed by
// pinning/reinstalling — so the two are tracked distinctly for remediation.
const (
	SourceTypeManifest  = "manifest"  // declared in a manifest/lockfile
	SourceTypeInstalled = "installed" // found in an install dir, not declared
)

// PackageChecksum holds one integrity hash extracted from a lock file.
type PackageChecksum struct {
	Alg   string // CycloneDX alg label: "SHA-256", "SHA-512", "SHA-1", "H1"
	Value string // hex or base64 string, stripped of the lock-file prefix
}

// normalizeChecksum parses and normalizes a raw checksum string into a PackageChecksum.
func normalizeChecksum(raw string) PackageChecksum {
	raw = strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(raw, "sha512-"):
		return PackageChecksum{"SHA-512", raw[7:]}
	case strings.HasPrefix(raw, "sha256:"):
		return PackageChecksum{"SHA-256", raw[7:]}
	case strings.HasPrefix(raw, "sha256-"):
		return PackageChecksum{"SHA-256", raw[7:]}
	case strings.HasPrefix(raw, "sha1:"):
		return PackageChecksum{"SHA-1", raw[5:]}
	case strings.HasPrefix(raw, "h1:"):
		return PackageChecksum{"H1", raw[3:]}
	case len(raw) == 64 && isHex(raw):
		return PackageChecksum{"SHA-256", raw}
	case len(raw) == 40 && isHex(raw):
		return PackageChecksum{"SHA-1", raw}
	}
	return PackageChecksum{}
}

// isHex returns true if all runes in s are valid hexadecimal characters.
func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// ScopeIcon returns a display icon for a scope category.
func ScopeIcon(scope string) string {
	switch scope {
	case ScopeProduction:
		return "📦"
	case ScopeDevelopment:
		return "🔧"
	case ScopeTest:
		return "🧪"
	case ScopePeer:
		return "🔗"
	case ScopeOptional:
		return "🔶"
	case ScopeProvided:
		return "📋"
	case ScopeRuntime:
		return "⚙️ "
	default:
		return "  "
	}
}

// ScopedPackage represents a parsed dependency with scope information.
type ScopedPackage struct {
	Name        string
	Version     string
	VersionSpec string // raw version spec from manifest before cleaning (e.g. "^1.0.0", ">=2.3"); empty for lock-file entries
	Ecosystem   string
	Scope       string            // native scope label (production, development, test, peer, etc.)
	SourceFile  string            // relative path of the manifest file that declared this package
	IsDirect    bool              // true if declared in the manifest (e.g., go.mod), false if transitive (e.g., go.sum)
	GitHubURL   string            // optional: "owner/repo" for packages whose VCS is known from the manifest
	Checksums   []PackageChecksum // per-package integrity hashes extracted from lock files

	// Discovery-source provenance (see SourceType* consts). SourceType is
	// "manifest" when the package was declared, "installed" when it was found only
	// in an install directory. InstalledPath is the root-relative install location
	// (e.g. "node_modules/lodash") for installed packages; empty otherwise.
	SourceType    string
	InstalledPath string

	// Container-image provenance (oci ecosystem only). RegistryType classifies the
	// image registry (dockerhub/gcr/ecr/acr/ghcr/gitlab/local/private);
	// IsPrivateRegistry is true when the host is not a well-known public registry.
	RegistryType      string
	IsPrivateRegistry bool
}

// ParseManifestWithScope parses a manifest file and returns packages with scope information.
// It uses the file's manifest type to choose the appropriate parser.
func ParseManifestWithScope(filePath, manifestType string) ([]ScopedPackage, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", filePath, err)
	}

	switch manifestType {
	case "package.json":
		return parsePackageJSONScoped(data, filePath)
	case "package-lock.json":
		return parsePackageLockJSONScoped(data, filePath)
	case "yarn.lock":
		return parseYarnLockScoped(data, filePath)
	case "pnpm-lock.yaml":
		return parsePnpmLockScoped(data, filePath)
	case "requirements.txt":
		return parseRequirementsTxtScoped(data, filePath)
	case "Pipfile.lock":
		return parsePipfileLockScoped(data, filePath)
	case "uv.lock":
		return parseUVLockScoped(data, filePath)
	case "pylock.toml":
		return parsePylockTOMLScoped(data, filePath)
	case "pyproject.toml":
		return parsePyprojectTOMLScoped(data, filePath)
	case "setup.py":
		return parseSetupPyScoped(data, filePath)
	case "setup.cfg":
		return parseSetupCfgScoped(data, filePath)
	// ── Conda ─────────────────────────────────────────────────────────────
	case "environment.yml":
		return parseCondaEnvScoped(data, filePath)
	case "go.sum":
		return parseGoSumScoped(data, filePath)
	case "go.mod":
		return parseGoModScoped(data, filePath)
	case "Cargo.lock":
		return parseCargoLockScoped(data, filePath)
	case "Gemfile.lock":
		return parseGemfileLockScoped(data, filePath)
	case "pom.xml":
		return parsePomXMLScoped(data, filePath)
	case "composer.lock":
		return parseComposerLockScoped(data, filePath)
	// ── Python ────────────────────────────────────────────────────────────
	case "requirements.in":
		return parseRequirementsTxtScoped(data, filePath)
	case "Pipfile":
		return parsePipfileScoped(data, filePath)
	case "poetry.lock":
		return parsePoetryLockScoped(data, filePath)
	// ── Ruby ──────────────────────────────────────────────────────────────
	case "Gemfile":
		return parseGemfileScoped(data, filePath)
	// ── Rust ──────────────────────────────────────────────────────────────
	case "Cargo.toml":
		return parseCargoTomlScoped(data, filePath)
	// ── Java / Gradle ─────────────────────────────────────────────────────
	case "build.gradle":
		return parseGradleScoped(data, filePath)
	case "build.gradle.kts":
		return parseGradleKtsScoped(data, filePath)
	case "gradle.lockfile":
		return parseGradleLockfileScoped(data, filePath)
	// ── PHP / Composer ────────────────────────────────────────────────────
	case "composer.json":
		return parseComposerJSONScoped(data, filePath)
	// ── .NET / NuGet ──────────────────────────────────────────────────────
	case "packages.lock.json":
		return parseNugetLockScoped(data, filePath)
	case "paket.dependencies":
		return parsePaketDepsScoped(data, filePath)
	case "paket.lock":
		return parsePaketLockScoped(data, filePath)
	case "*.csproj":
		return parseCsprojScoped(data, filePath)
	case "packages.config":
		return parsePackagesConfigScoped(data, filePath)
	// ── Clojure (Leiningen / tools.deps / Babashka) ───────────────────────
	case "project.clj":
		return parseLeiningenScoped(data, filePath)
	case "deps.edn":
		return parseDepsEdnScoped(data, filePath)
	// ── Swift ─────────────────────────────────────────────────────────────
	case "Package.swift":
		return parsePackageSwiftScoped(data, filePath)
	case "Package.resolved":
		return parsePackageResolvedScoped(data, filePath)
	// ── Dart / Flutter ────────────────────────────────────────────────────
	case "pubspec.yaml":
		return parsePubspecYAMLScoped(data, filePath)
	case "pubspec.lock":
		return parsePubspecLockScoped(data, filePath)
	// ── Elixir ────────────────────────────────────────────────────────────
	case "mix.exs":
		return parseMixScoped(data, filePath)
	case "mix.lock":
		return parseMixLockScoped(data, filePath)
	// ── Scala / sbt ───────────────────────────────────────────────────────
	case "build.sbt":
		return parseBuildSbtScoped(data, filePath)
	case "build.lock":
		return parseBuildLockScoped(data, filePath)
	case "build.sc":
		return parseMillScoped(data, filePath)
	// ── Docker ────────────────────────────────────────────────────────────
	case "Dockerfile":
		return parseDockerfileScoped(data, filePath)
	case "compose.yaml":
		return parseComposeScoped(data, filePath)
	// ── Kubernetes / Helm ─────────────────────────────────────────────────
	case "kubernetes.yaml":
		return parseKubernetesScoped(data, filePath)
	case "Chart.yaml":
		return parseHelmChartScoped(data, filePath)
	// ── GitHub Actions ────────────────────────────────────────────────────
	case "github-actions.yml":
		return parseGithubActionsScoped(data, filePath)
	// ── Terraform ─────────────────────────────────────────────────────────
	case "*.tf":
		return parseTerraformScoped(data, filePath)
	// ── C/C++ / Conan ─────────────────────────────────────────────────────
	case "conanfile.txt":
		return parseConanfileScoped(data, filePath)
	case "conan.lock":
		return parseConanLockScoped(data, filePath)
	// ── C/C++ / vcpkg ─────────────────────────────────────────────────────
	case "vcpkg.json":
		return parseVcpkgJSONScoped(data, filePath)
	// ── CocoaPods ─────────────────────────────────────────────────────────
	case "Podfile":
		return parsePodfileScoped(data, filePath)
	case "Podfile.lock":
		return parsePodfileLockScoped(data, filePath)
	// ── Carthage ──────────────────────────────────────────────────────────
	case "Cartfile":
		return parseCartfileScoped(data, filePath)
	case "Cartfile.resolved":
		return parseCartfileResolvedScoped(data, filePath)
	// ── Julia ─────────────────────────────────────────────────────────────
	case "Project.toml":
		return parseProjectTomlScoped(data, filePath)
	case "Manifest.toml":
		return parseManifestTomlScoped(data, filePath)
	// ── Crystal ───────────────────────────────────────────────────────────
	case "shard.yml":
		return parseShardYAMLScoped(data, filePath)
	case "shard.lock":
		return parseShardLockScoped(data, filePath)
	// ── Deno ──────────────────────────────────────────────────────────────
	case "deno.json":
		return parseDenoJSONScoped(data, filePath)
	case "deno.lock":
		return parseDenoLockScoped(data, filePath)
	// ── R / CRAN ──────────────────────────────────────────────────────────
	case "DESCRIPTION":
		return parseDescriptionScoped(data, filePath)
	case "renv.lock":
		return parseRenvLockScoped(data, filePath)
	// ── Erlang / rebar3 ───────────────────────────────────────────────────
	case "rebar.config":
		return parseRebarConfigScoped(data, filePath)
	case "rebar.lock":
		return parseRebarLockScoped(data, filePath)
	// ── Haskell / Stack ───────────────────────────────────────────────────
	case "stack.yaml":
		return parseStackYAMLScoped(data, filePath)
	// ── Haskell / Cabal ───────────────────────────────────────────────────
	case "*.cabal":
		return parseCabalScoped(data, filePath)
	case "cabal.project.freeze":
		return parseCabalFreezeScoped(data, filePath)
	// ── OCaml / opam ──────────────────────────────────────────────────────
	case "*.opam":
		return parseOpamScoped(data, filePath)
	case "opam":
		return parseOpamScoped(data, filePath)
	// ── Nix ───────────────────────────────────────────────────────────────
	case "flake.nix":
		return parseFlakeNixScoped(data, filePath)
	case "flake.lock":
		return parseFlakeLockScoped(data, filePath)
	// ── Zig ───────────────────────────────────────────────────────────────
	case "build.zig.zon":
		return parseZigZonScoped(data, filePath)
	// ── CMake / CPM ───────────────────────────────────────────────────────
	case "CPM.cmake", "CMakeLists.txt":
		return parseCPMCmakeScoped(data, filePath)
	// ── Meson ─────────────────────────────────────────────────────────────
	case "meson.build":
		return parseMesonBuildScoped(data, filePath)
	// ── Bazel ─────────────────────────────────────────────────────────────
	case "WORKSPACE":
		return parseWorkspaceScoped(data, filePath)
	case "MODULE.bazel":
		return parseModuleBazelScoped(data, filePath)
	// ── Buck ──────────────────────────────────────────────────────────────
	case "BUCK", "BUCK2":
		return parseBuckScoped(data, filePath)
	default:
		return nil, fmt.Errorf("unsupported manifest type: %s", manifestType)
	}
}

// ---------------------------------------------------------------------------
// npm
// ---------------------------------------------------------------------------

func parsePackageJSONScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	var pkg struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("invalid package.json: %w", err)
	}

	var pkgs []ScopedPackage
	for name, ver := range pkg.Dependencies {
		pkgs = append(pkgs, ScopedPackage{Name: name, Version: cleanLocalVersion(ver), VersionSpec: ver, Ecosystem: "npm", Scope: ScopeProduction, SourceFile: filePath, IsDirect: true})
	}
	for name, ver := range pkg.DevDependencies {
		pkgs = append(pkgs, ScopedPackage{Name: name, Version: cleanLocalVersion(ver), VersionSpec: ver, Ecosystem: "npm", Scope: ScopeDevelopment, SourceFile: filePath, IsDirect: true})
	}
	for name, ver := range pkg.PeerDependencies {
		pkgs = append(pkgs, ScopedPackage{Name: name, Version: cleanLocalVersion(ver), VersionSpec: ver, Ecosystem: "npm", Scope: ScopePeer, SourceFile: filePath, IsDirect: true})
	}
	for name, ver := range pkg.OptionalDependencies {
		pkgs = append(pkgs, ScopedPackage{Name: name, Version: cleanLocalVersion(ver), VersionSpec: ver, Ecosystem: "npm", Scope: ScopeOptional, SourceFile: filePath, IsDirect: true})
	}
	return pkgs, nil
}

func parsePackageLockJSONScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	// Supports both v1/v2 (dependencies) and v3 (packages) formats.
	var lock struct {
		LockfileVersion int `json:"lockfileVersion"`
		Packages        map[string]struct {
			Version     string `json:"version"`
			Dev         bool   `json:"dev"`
			DevOptional bool   `json:"devOptional"`
			Optional    bool   `json:"optional"`
			Peer        bool   `json:"peer"`
			Integrity   string `json:"integrity"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version   string `json:"version"`
			Dev       bool   `json:"dev"`
			Optional  bool   `json:"optional"`
			Integrity string `json:"integrity"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("invalid package-lock.json: %w", err)
	}

	var pkgs []ScopedPackage
	seen := make(map[string]bool)

	// v3 format: packages field
	for path, pkg := range lock.Packages {
		if path == "" {
			continue // root package entry
		}
		name := path
		if strings.HasPrefix(path, "node_modules/") {
			name = strings.TrimPrefix(path, "node_modules/")
		}
		if seen[name] {
			continue
		}
		seen[name] = true

		scope := ScopeProduction
		if pkg.Dev || pkg.DevOptional {
			scope = ScopeDevelopment
		} else if pkg.Peer {
			scope = ScopePeer
		} else if pkg.Optional {
			scope = ScopeOptional
		}
		sp := ScopedPackage{Name: name, Version: pkg.Version, Ecosystem: "npm", Scope: scope, SourceFile: filePath}
		if c := normalizeChecksum(pkg.Integrity); c.Alg != "" {
			sp.Checksums = []PackageChecksum{c}
		}
		pkgs = append(pkgs, sp)
	}

	// v1/v2 format: dependencies field
	for name, pkg := range lock.Dependencies {
		if seen[name] {
			continue
		}
		seen[name] = true

		scope := ScopeProduction
		if pkg.Dev {
			scope = ScopeDevelopment
		} else if pkg.Optional {
			scope = ScopeOptional
		}
		sp := ScopedPackage{Name: name, Version: pkg.Version, Ecosystem: "npm", Scope: scope, SourceFile: filePath}
		if c := normalizeChecksum(pkg.Integrity); c.Alg != "" {
			sp.Checksums = []PackageChecksum{c}
		}
		pkgs = append(pkgs, sp)
	}
	return pkgs, nil
}

func parseYarnLockScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	// yarn.lock does not embed scope information; all packages are listed as production.
	// Scope would require correlation with package.json which is not done here.
	// Handles both yarn classic v1 and yarn berry v2/v3/v4 formats.
	var pkgs []ScopedPackage
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	var currentName, currentIntegrity string

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Package header: non-indented line containing '@' (not a comment or metadata).
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' &&
			line[0] != '#' && strings.Contains(line, "@") {
			// Strip outer quotes and trailing colon.
			cleaned := strings.TrimRight(trimmed, ":")
			cleaned = strings.Trim(cleaned, `"`)
			// Yarn berry lists comma-separated specifiers on one header line;
			// take the first one only.
			if idx := strings.Index(cleaned, ", "); idx > 0 {
				cleaned = cleaned[:idx]
			}
			// Strip yarn berry registry prefix inside specifier (e.g. "@scope/pkg@npm:^1.0")
			// We want just the package name — everything before the last '@'.
			if strings.HasPrefix(cleaned, "@") {
				// Scoped: @scope/name@specifier
				idx := strings.LastIndex(cleaned, "@")
				if idx > 0 {
					currentName = cleaned[:idx]
				}
			} else {
				idx := strings.Index(cleaned, "@")
				if idx > 0 {
					currentName = cleaned[:idx]
				}
			}
			currentIntegrity = ""
			continue
		}

		if currentName == "" {
			continue
		}

		// Integrity/checksum line.
		// Classic v1: integrity sha512-...
		// Berry v4: checksum: ...
		switch {
		case strings.HasPrefix(trimmed, "integrity "):
			currentIntegrity = strings.Trim(strings.TrimPrefix(trimmed, "integrity "), `"`)
		case strings.HasPrefix(trimmed, "checksum: "):
			currentIntegrity = strings.Trim(strings.TrimPrefix(trimmed, "checksum: "), `"`)
		}

		// Resolved version line.
		// Classic v1:  version "1.2.3"
		// Berry v4:    version: 1.2.3
		var version string
		switch {
		case strings.HasPrefix(trimmed, "version \"") || strings.HasPrefix(trimmed, "version '"):
			version = strings.Trim(strings.TrimPrefix(trimmed, "version "), `"'`)
		case strings.HasPrefix(trimmed, "version: "):
			version = strings.TrimSpace(strings.TrimPrefix(trimmed, "version: "))
			version = strings.Trim(version, `"'`)
		}

		if version != "" {
			key := currentName + "@" + version
			if !seen[key] {
				seen[key] = true
				sp := ScopedPackage{Name: currentName, Version: version, Ecosystem: "npm", Scope: ScopeProduction, SourceFile: filePath}
				if c := normalizeChecksum(currentIntegrity); c.Alg != "" {
					sp.Checksums = []PackageChecksum{c}
				}
				pkgs = append(pkgs, sp)
			}
			currentName = ""
		}
	}
	return pkgs, nil
}

func parsePnpmLockScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	// The packages section of pnpm-lock.yaml doesn't differentiate dev/prod.
	// Full scope would require parsing importers sections.
	var pkgs []ScopedPackage
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	inPackages := false
	var currentName, currentVersion, currentIntegrity string

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "packages:" {
			inPackages = true
			continue
		}
		if inPackages && len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			if currentName != "" && currentVersion != "" {
				key := currentName + "@" + currentVersion
				if !seen[key] {
					seen[key] = true
					sp := ScopedPackage{Name: currentName, Version: currentVersion, Ecosystem: "npm", Scope: ScopeProduction, SourceFile: filePath}
					if c := normalizeChecksum(currentIntegrity); c.Alg != "" {
						sp.Checksums = []PackageChecksum{c}
					}
					pkgs = append(pkgs, sp)
				}
			}
			currentName, currentVersion, currentIntegrity = "", "", ""
			inPackages = false
			continue
		}

		if inPackages {
			if strings.HasPrefix(trimmed, "/") && strings.Contains(trimmed, "@") {
				entry := strings.TrimPrefix(strings.TrimSuffix(trimmed, ":"), "/")
				lastAt := strings.LastIndex(entry, "@")
				if lastAt > 0 {
					currentName = entry[:lastAt]
					currentVersion = entry[lastAt+1:]
				}
			} else if strings.HasPrefix(trimmed, "integrity:") {
				currentIntegrity = strings.Trim(strings.TrimPrefix(trimmed, "integrity:"), `"`)
			}
		}
	}
	if inPackages && currentName != "" && currentVersion != "" {
		key := currentName + "@" + currentVersion
		if !seen[key] {
			seen[key] = true
			sp := ScopedPackage{Name: currentName, Version: currentVersion, Ecosystem: "npm", Scope: ScopeProduction, SourceFile: filePath}
			if c := normalizeChecksum(currentIntegrity); c.Alg != "" {
				sp.Checksums = []PackageChecksum{c}
			}
			pkgs = append(pkgs, sp)
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Python
// ---------------------------------------------------------------------------

// parseRequirementsTxtScoped parses a pip requirements file (requirements.txt,
// requirements.in, or any content-detected variant). It handles the full shape
// emitted by `pip freeze` and `uv/pip compile --generate-hashes`:
//   - `\` line continuations joining a requirement to its `--hash=` lines,
//   - multiple `--hash=ALG:VALUE` tokens per package (sdist + every wheel),
//   - the trailing `# via` comment block, which encodes how a package entered the
//     resolution: a `-r <file>`/`-c <file>` source means the package is a direct
//     requirement; otherwise (only parent package names) it is transitive.
//
// requirements.txt has no prod/dev scope concept, so all deps are production.
func parseRequirementsTxtScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	var pkgs []ScopedPackage

	// 1. Join backslash continuations into logical lines (comment lines are never
	//    continued, so a `# via` block stays one logical line per entry).
	logical := joinReqContinuations(string(data))

	// 2. Walk logical lines. A `# via` block annotates the package that preceded
	//    it; a package is direct unless its via block lists only parent packages.
	curIdx := -1       // pkgs index the current via block annotates
	curVia := false    // saw a `via` marker for the current package
	curDirect := false // via block referenced an -r/-c include (a direct source)

	finalize := func() {
		if curIdx >= 0 && curVia && !curDirect {
			pkgs[curIdx].IsDirect = false
		}
		curVia, curDirect = false, false
	}

	for _, ll := range logical {
		line := strings.TrimSpace(ll)
		if line == "" {
			continue
		}

		// Comment line: possibly part of the current package's `# via` block.
		if strings.HasPrefix(line, "#") {
			if curIdx < 0 {
				continue
			}
			body := strings.TrimSpace(strings.TrimPrefix(line, "#"))
			if rest, ok := strings.CutPrefix(body, "via"); ok {
				curVia = true
				body = strings.TrimSpace(rest)
			}
			if curVia && body != "" && isRequirementsInclude(body) {
				curDirect = true
			}
			continue
		}

		// Any non-comment line ends the previous package's via block.
		finalize()
		curIdx = -1

		// Strip an inline trailing comment (" # note"); not present on hash lines.
		if ci := strings.Index(line, " #"); ci >= 0 {
			line = strings.TrimSpace(line[:ci])
		}

		// Directives (-r/-c/-e/-i/--index-url/--hash on its own/…).
		if strings.HasPrefix(line, "-") {
			if name := editableEggName(line); name != "" {
				pkgs = append(pkgs, ScopedPackage{Name: name, Ecosystem: "pypi", Scope: ScopeProduction, SourceFile: filePath, IsDirect: true})
				curIdx = len(pkgs) - 1
			}
			continue
		}

		// Separate the requirement spec from any trailing --hash= tokens.
		var specParts []string
		var checksums []PackageChecksum
		for _, tok := range strings.Fields(line) {
			if h, ok := strings.CutPrefix(tok, "--hash="); ok {
				if c := normalizeChecksum(strings.TrimSpace(h)); c.Alg != "" {
					checksums = append(checksums, c)
				}
				continue
			}
			specParts = append(specParts, tok)
		}
		name, version, versionSpec, ok := parsePEP508(strings.Join(specParts, " "))
		if !ok || name == "" {
			continue
		}
		pkgs = append(pkgs, ScopedPackage{
			Name: name, Version: version, VersionSpec: versionSpec,
			Ecosystem: "pypi", Scope: ScopeProduction, SourceFile: filePath,
			IsDirect: true, Checksums: checksums,
		})
		curIdx = len(pkgs) - 1
	}
	finalize()
	return pkgs, nil
}

// joinReqContinuations splits requirements-file text into logical lines, joining
// `\`-continuation lines (so a requirement and its trailing `--hash=` lines form
// one record). Comment lines are never continued.
func joinReqContinuations(data string) []string {
	raw := strings.Split(strings.ReplaceAll(data, "\r\n", "\n"), "\n")
	var logical []string
	var buf strings.Builder
	for _, ln := range raw {
		if strings.HasSuffix(strings.TrimRight(ln, " \t"), `\`) {
			buf.WriteString(strings.TrimSuffix(strings.TrimRight(ln, " \t"), `\`))
			buf.WriteString(" ")
			continue
		}
		buf.WriteString(ln)
		logical = append(logical, buf.String())
		buf.Reset()
	}
	if buf.Len() > 0 {
		logical = append(logical, buf.String())
	}
	return logical
}

// parsePEP508 parses a PEP 508 requirement specifier (e.g. "PyYAML[yaml]>=6.0 ;
// python_version>='3.8'"). It strips extras and environment markers, splits on
// the version operator, and supports bare names (no version). Returns the name,
// the cleaned exact version (first version token), the full version spec
// (operator+version), and ok=false for non-requirement input.
func parsePEP508(raw string) (name, version, versionSpec string, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") {
		return "", "", "", false
	}
	// Strip environment markers ("pkg>=1.0 ; python_version>='3.8'").
	if idx := strings.Index(raw, ";"); idx >= 0 {
		raw = strings.TrimSpace(raw[:idx])
	}
	// Strip extras ("pkg[extra]>=1.0").
	if bIdx := strings.Index(raw, "["); bIdx > 0 {
		if eIdx := strings.Index(raw, "]"); eIdx > bIdx {
			raw = strings.TrimSpace(raw[:bIdx] + raw[eIdx+1:])
		}
	}
	if raw == "" {
		return "", "", "", false
	}
	for _, sep := range []string{"===", "==", ">=", "<=", "~=", "!=", ">", "<"} {
		if idx := strings.Index(raw, sep); idx > 0 {
			return strings.TrimSpace(raw[:idx]),
				cleanReqVersion(raw[idx+len(sep):]),
				strings.TrimSpace(raw[idx:]),
				true
		}
	}
	// Bare name (no version specifier).
	return raw, "", "", true
}

// cleanReqVersion returns the first version token from a (possibly multi-clause)
// version string, e.g. ">=1.0,<2.0" → "1.0".
func cleanReqVersion(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.IndexAny(v, ", "); i >= 0 {
		v = v[:i]
	}
	return v
}

// isRequirementsInclude reports whether a `# via` token is an -r/-c file include
// (which marks the annotated package as a direct requirement) rather than a
// parent package name.
func isRequirementsInclude(s string) bool {
	s = strings.TrimSpace(s)
	return s == "-r" || s == "-c" ||
		strings.HasPrefix(s, "-r ") || strings.HasPrefix(s, "-c ") ||
		strings.HasPrefix(s, "--requirement") || strings.HasPrefix(s, "--constraint")
}

// editableEggName extracts the package name from an editable/VCS requirement
// (e.g. "-e git+https://host/repo.git#egg=name"). Returns "" when absent.
func editableEggName(line string) string {
	i := strings.Index(line, "#egg=")
	if i < 0 {
		return ""
	}
	name := line[i+len("#egg="):]
	if j := strings.IndexAny(name, " \t&"); j >= 0 {
		name = name[:j]
	}
	return strings.TrimSpace(name)
}

func parsePipfileLockScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	// Pipfile.lock separates [default] (production) from [develop] (development).
	var lock struct {
		Default map[string]struct {
			Version string   `json:"version"`
			Hashes  []string `json:"hashes"`
		} `json:"default"`
		Develop map[string]struct {
			Version string   `json:"version"`
			Hashes  []string `json:"hashes"`
		} `json:"develop"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("invalid Pipfile.lock: %w", err)
	}

	var pkgs []ScopedPackage
	for name, pkg := range lock.Default {
		sp := ScopedPackage{Name: name, Version: cleanLocalVersion(pkg.Version), Ecosystem: "pypi", Scope: ScopeProduction, SourceFile: filePath}
		for _, h := range pkg.Hashes {
			if c := normalizeChecksum(h); c.Alg != "" {
				sp.Checksums = append(sp.Checksums, c)
			}
		}
		pkgs = append(pkgs, sp)
	}
	for name, pkg := range lock.Develop {
		sp := ScopedPackage{Name: name, Version: cleanLocalVersion(pkg.Version), Ecosystem: "pypi", Scope: ScopeDevelopment, SourceFile: filePath}
		for _, h := range pkg.Hashes {
			if c := normalizeChecksum(h); c.Alg != "" {
				sp.Checksums = append(sp.Checksums, c)
			}
		}
		pkgs = append(pkgs, sp)
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Python (uv.lock + pyproject.toml)
// ---------------------------------------------------------------------------

// uvLockArtifact / uvLockDep / uvLockPackage / uvLockFile decode a uv.lock file.
// uv.lock uses inline tables (`sdist = { url=…, hash="sha256:…" }`, `wheels =
// [{…},…]`, `dependencies = [{ name=… }]`), which a real TOML decoder reads
// losslessly — the previous hand-rolled scanner missed all of it.
type uvLockArtifact struct {
	URL  string `toml:"url"`
	Hash string `toml:"hash"`
}
type uvLockDep struct {
	Name string `toml:"name"`
}
type uvLockPackage struct {
	Name                 string                 `toml:"name"`
	Version              string                 `toml:"version"`
	Sdist                *uvLockArtifact        `toml:"sdist"`
	Wheels               []uvLockArtifact       `toml:"wheels"`
	Dependencies         []uvLockDep            `toml:"dependencies"`
	OptionalDependencies map[string][]uvLockDep `toml:"optional-dependencies"`
}
type uvLockFile struct {
	Package []uvLockPackage `toml:"package"`
}

// parseUVLockScoped parses a uv.lock file (TOML, [[package]] tables). It captures
// every sdist + wheel hash. uv.lock does not encode prod/dev scope per-package,
// so all packages are marked production; the dependency tree (the `dependencies`
// tables) is consumed separately by PopulatePypiLockEdges for the SBOM graph.
func parseUVLockScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	var lock uvLockFile
	if _, err := toml.Decode(string(data), &lock); err != nil {
		return nil, fmt.Errorf("invalid uv.lock: %w", err)
	}
	var pkgs []ScopedPackage
	for _, p := range lock.Package {
		if p.Name == "" {
			continue
		}
		sp := ScopedPackage{Name: p.Name, Version: p.Version, Ecosystem: "pypi", Scope: ScopeProduction, SourceFile: filePath}
		if p.Sdist != nil {
			if c := normalizeChecksum(p.Sdist.Hash); c.Alg != "" {
				sp.Checksums = append(sp.Checksums, c)
			}
		}
		for _, w := range p.Wheels {
			if c := normalizeChecksum(w.Hash); c.Alg != "" {
				sp.Checksums = append(sp.Checksums, c)
			}
		}
		pkgs = append(pkgs, sp)
	}
	return pkgs, nil
}

// pylockHashes / pylockArtifact / pylockPackage / pylockFile decode a PEP 751
// pylock.toml. Hashes are a sub-table keyed by algorithm with bare-hex values
// (`hashes = { sha256 = "HEX" }`), unlike uv.lock's prefixed `hash = "sha256:…"`.
type pylockHashes struct {
	SHA256 string `toml:"sha256"`
	SHA512 string `toml:"sha512"`
	SHA1   string `toml:"sha1"`
}
type pylockArtifact struct {
	URL    string       `toml:"url"`
	Hashes pylockHashes `toml:"hashes"`
}
type pylockPackage struct {
	Name         string           `toml:"name"`
	Version      string           `toml:"version"`
	Sdist        *pylockArtifact  `toml:"sdist"`
	Wheels       []pylockArtifact `toml:"wheels"`
	Dependencies []struct {
		Name string `toml:"name"`
	} `toml:"dependencies"`
}
type pylockFile struct {
	Packages []pylockPackage `toml:"packages"`
}

// parsePylockTOMLScoped parses a PEP 751 pylock.toml lock file, capturing every
// sdist + wheel hash per package. pylock.toml is a fully-pinned lock, so all
// entries are production with exact versions.
func parsePylockTOMLScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	var lock pylockFile
	if _, err := toml.Decode(string(data), &lock); err != nil {
		return nil, fmt.Errorf("invalid pylock.toml: %w", err)
	}
	var pkgs []ScopedPackage
	for _, p := range lock.Packages {
		if p.Name == "" {
			continue
		}
		sp := ScopedPackage{Name: p.Name, Version: p.Version, Ecosystem: "pypi", Scope: ScopeProduction, SourceFile: filePath}
		addPylockHashes(&sp, p.Sdist)
		for i := range p.Wheels {
			addPylockHashes(&sp, &p.Wheels[i])
		}
		pkgs = append(pkgs, sp)
	}
	return pkgs, nil
}

// addPylockHashes appends the algorithm-keyed bare-hex hashes of a pylock.toml
// artifact (sdist or wheel) to the package's checksum list.
func addPylockHashes(sp *ScopedPackage, a *pylockArtifact) {
	if a == nil {
		return
	}
	if a.Hashes.SHA256 != "" {
		sp.Checksums = append(sp.Checksums, PackageChecksum{Alg: "SHA-256", Value: a.Hashes.SHA256})
	}
	if a.Hashes.SHA512 != "" {
		sp.Checksums = append(sp.Checksums, PackageChecksum{Alg: "SHA-512", Value: a.Hashes.SHA512})
	}
	if a.Hashes.SHA1 != "" {
		sp.Checksums = append(sp.Checksums, PackageChecksum{Alg: "SHA-1", Value: a.Hashes.SHA1})
	}
}

// parsePyprojectTOMLScoped parses a pyproject.toml file without a TOML library.
// It extracts:
//   - [project] dependencies            → ScopeProduction, IsDirect=true
//   - [project.optional-dependencies]   → ScopeTest / ScopeDevelopment / ScopeOptional
//   - [dependency-groups]               → ScopeTest / ScopeDevelopment / ScopeOptional
//   - [tool.uv] dev-dependencies        → ScopeDevelopment
func parsePyprojectTOMLScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	var pkgs []ScopedPackage
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	const (
		secNone        = ""
		secProjectDeps = "project.dependencies"
		secOptional    = "project.optional-dependencies"
		secDepGroups   = "dependency-groups"
		secUVTool      = "tool.uv"
	)

	currentSection := secNone
	inArray := false
	currentScope := ScopeProduction

	// mapGroupScope converts a dependency-group name to a scope.
	mapGroupScope := func(group string) string {
		switch strings.ToLower(group) {
		case "test", "tests", "testing":
			return ScopeTest
		case "dev", "develop", "development", "devel":
			return ScopeDevelopment
		default:
			return ScopeOptional
		}
	}

	// extractPyDep parses a TOML array item holding a PEP 508 dependency specifier
	// (e.g. `"PyYAML>=6.0",`). It strips TOML quoting/commas and group-include
	// dicts, then defers to parsePEP508 for the actual specifier parsing.
	extractPyDep := func(raw string) (name, ver, versionSpec string, ok bool) {
		raw = strings.TrimSpace(raw)
		raw = strings.Trim(raw, `"',`)
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "{") || strings.HasPrefix(raw, "#") {
			return "", "", "", false
		}
		return parsePEP508(raw)
	}

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip comments.
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Section header (skip [[...]] table arrays that aren't dependency sections).
		if strings.HasPrefix(trimmed, "[") {
			inArray = false
			// Strip [[ ]] for array-of-tables, or [ ] for regular tables.
			secRaw := strings.TrimLeft(trimmed, "[")
			secRaw = strings.TrimRight(secRaw, "]")
			secRaw = strings.TrimSpace(secRaw)
			switch secRaw {
			case "project":
				currentSection = secNone // We only want [project].dependencies key, handled below.
			case "project.optional-dependencies":
				currentSection = secOptional
			case "dependency-groups":
				currentSection = secDepGroups
			case "tool.uv":
				currentSection = secUVTool
			default:
				currentSection = secNone
			}
			continue
		}

		if inArray {
			// End of multi-line array.
			if trimmed == "]" || strings.HasPrefix(trimmed, "]") {
				inArray = false
				continue
			}
			if name, ver, spec, ok := extractPyDep(trimmed); ok {
				isDirect := currentScope == ScopeProduction
				pkgs = append(pkgs, ScopedPackage{
					Name: name, Version: ver, VersionSpec: spec,
					Ecosystem: "pypi", Scope: currentScope,
					SourceFile: filePath, IsDirect: isDirect,
				})
			}
			continue
		}

		// Look for key = [ array openers.
		// Detect the key name and any inline content.
		if idx := strings.Index(trimmed, "="); idx > 0 {
			key := strings.TrimSpace(trimmed[:idx])
			rest := strings.TrimSpace(trimmed[idx+1:])

			// Handle [project] dependencies key regardless of what section tracker says.
			if key == "dependencies" && strings.HasPrefix(rest, "[") {
				// Only treat as production deps when we're in the [project] section
				// (not under [project.optional-dependencies] or [tool.*]).
				if currentSection == secNone {
					currentScope = ScopeProduction
					// Inline single-line array: dependencies = ["a", "b"]
					if strings.HasSuffix(rest, "]") {
						inner := strings.TrimSuffix(strings.TrimPrefix(rest, "["), "]")
						for _, item := range strings.Split(inner, ",") {
							if n, v, spec, ok := extractPyDep(item); ok {
								pkgs = append(pkgs, ScopedPackage{
									Name: n, Version: v, VersionSpec: spec,
									Ecosystem: "pypi", Scope: currentScope,
									SourceFile: filePath, IsDirect: true,
								})
							}
						}
					} else {
						inArray = true
					}
					continue
				}
			}

			// Handle [tool.uv] dev-dependencies.
			if currentSection == secUVTool && key == "dev-dependencies" && strings.HasPrefix(rest, "[") {
				currentScope = ScopeDevelopment
				if strings.HasSuffix(rest, "]") {
					inner := strings.TrimSuffix(strings.TrimPrefix(rest, "["), "]")
					for _, item := range strings.Split(inner, ",") {
						if n, v, spec, ok := extractPyDep(item); ok {
							pkgs = append(pkgs, ScopedPackage{
								Name: n, Version: v, VersionSpec: spec,
								Ecosystem: "pypi", Scope: currentScope,
								SourceFile: filePath, IsDirect: true,
							})
						}
					}
				} else {
					inArray = true
				}
				continue
			}

			// Handle named group keys in [project.optional-dependencies] and [dependency-groups].
			if (currentSection == secOptional || currentSection == secDepGroups) && strings.HasPrefix(rest, "[") {
				currentScope = mapGroupScope(key)
				if strings.HasSuffix(rest, "]") {
					inner := strings.TrimSuffix(strings.TrimPrefix(rest, "["), "]")
					for _, item := range strings.Split(inner, ",") {
						if n, v, spec, ok := extractPyDep(item); ok {
							pkgs = append(pkgs, ScopedPackage{
								Name: n, Version: v, VersionSpec: spec,
								Ecosystem: "pypi", Scope: currentScope,
								SourceFile: filePath, IsDirect: true,
							})
						}
					}
				} else {
					inArray = true
				}
				continue
			}
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Go
// ---------------------------------------------------------------------------

func parseGoSumScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	// Go modules don't separate dev/prod deps; all are production.
	var pkgs []ScopedPackage
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		name := parts[0]
		version := parts[1]
		if strings.HasSuffix(version, "/go.mod") {
			continue
		}
		version = strings.TrimPrefix(version, "v")
		key := name + "@" + version
		if !seen[key] {
			seen[key] = true
			sp := ScopedPackage{Name: name, Version: version, Ecosystem: "golang", Scope: ScopeProduction, SourceFile: filePath, IsDirect: false}
			if c := normalizeChecksum(parts[2]); c.Alg != "" {
				sp.Checksums = []PackageChecksum{c}
			}
			pkgs = append(pkgs, sp)
		}
	}
	return pkgs, nil
}

func parseGoModScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	var pkgs []ScopedPackage
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	inRequire := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "require (") || strings.HasPrefix(line, "require(") {
			inRequire = true
			continue
		}
		if line == ")" {
			inRequire = false
			continue
		}
		if strings.HasPrefix(line, "require ") && !strings.Contains(line, "(") {
			rest := strings.TrimPrefix(line, "require ")
			parts := strings.Fields(rest)
			if len(parts) >= 2 {
				pkgs = append(pkgs, ScopedPackage{Name: parts[0], Version: strings.TrimPrefix(parts[1], "v"), Ecosystem: "golang", Scope: ScopeProduction, SourceFile: filePath, IsDirect: true})
			}
			continue
		}
		if inRequire {
			parts := strings.Fields(line)
			if len(parts) >= 2 && !strings.HasPrefix(parts[0], "//") {
				pkgs = append(pkgs, ScopedPackage{Name: parts[0], Version: strings.TrimPrefix(parts[1], "v"), Ecosystem: "golang", Scope: ScopeProduction, SourceFile: filePath, IsDirect: true})
			}
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Rust
// ---------------------------------------------------------------------------

func parseCargoLockScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	// Cargo.lock does not distinguish dev-dependencies; scope comes from Cargo.toml.
	var pkgs []ScopedPackage
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	var name, version, checksum string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "[[package]]" {
			if name != "" {
				sp := ScopedPackage{Name: name, Version: version, Ecosystem: "cargo", Scope: ScopeProduction, SourceFile: filePath}
				if c := normalizeChecksum(checksum); c.Alg != "" {
					sp.Checksums = []PackageChecksum{c}
				}
				pkgs = append(pkgs, sp)
			}
			name, version, checksum = "", "", ""
			continue
		}
		if strings.HasPrefix(line, "name = ") {
			name = strings.Trim(strings.TrimPrefix(line, "name = "), "\"")
		}
		if strings.HasPrefix(line, "version = ") {
			version = strings.Trim(strings.TrimPrefix(line, "version = "), "\"")
		}
		if strings.HasPrefix(line, "checksum = ") {
			checksum = strings.Trim(strings.TrimPrefix(line, "checksum = "), "\"")
		}
	}
	if name != "" {
		sp := ScopedPackage{Name: name, Version: version, Ecosystem: "cargo", Scope: ScopeProduction, SourceFile: filePath}
		if c := normalizeChecksum(checksum); c.Alg != "" {
			sp.Checksums = []PackageChecksum{c}
		}
		pkgs = append(pkgs, sp)
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Ruby
// ---------------------------------------------------------------------------

func parseGemfileLockScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	// Gemfile.lock lists all specs; group info comes from Gemfile which isn't parsed here.
	// Under GEM/specs: a spec line is indented 4 spaces ("    name (version)") and its
	// dependency lines 6 spaces ("      dep (constraint)"). Earlier code treated the
	// 6-space dependency lines as packages too, producing garbage like actionpack@"=".
	// Bundler 2.5+ also emits a CHECKSUMS section ("  name (version) sha256=…").
	var pkgs []ScopedPackage
	checksums := map[string]PackageChecksum{} // "name@version" → checksum
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	inSpecs := false
	inChecksums := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " "))

		if trimmed == "specs:" {
			inSpecs, inChecksums = true, false
			continue
		}
		if trimmed == "CHECKSUMS" {
			inSpecs, inChecksums = false, true
			continue
		}
		// A non-indented, non-empty line ends the current section.
		if (inSpecs || inChecksums) && len(line) > 0 && line[0] != ' ' {
			inSpecs, inChecksums = false, false
		}

		switch {
		case inSpecs && indent == 4: // a spec (package)
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				pkgs = append(pkgs, ScopedPackage{Name: parts[0], Version: strings.Trim(parts[1], "()"), Ecosystem: "rubygems", Scope: ScopeProduction, SourceFile: filePath})
			}
		case inChecksums && indent == 2: // "name (version) sha256=HEX"
			parts := strings.Fields(trimmed)
			if len(parts) >= 3 {
				key := parts[0] + "@" + strings.Trim(parts[1], "()")
				if alg := strings.TrimPrefix(parts[2], "sha256="); alg != parts[2] {
					if c := normalizeChecksum("sha256:" + alg); c.Alg != "" {
						checksums[key] = c
					}
				}
			}
		}
	}
	for i := range pkgs {
		if c, ok := checksums[pkgs[i].Name+"@"+pkgs[i].Version]; ok {
			pkgs[i].Checksums = []PackageChecksum{c}
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Java / Maven
// ---------------------------------------------------------------------------

func parsePomXMLScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	// Maven uses <scope> tags: compile (default/production), test, provided, runtime, system.
	var pkgs []ScopedPackage
	content := string(data)
	depStart := 0
	for {
		idx := strings.Index(content[depStart:], "<dependency>")
		if idx < 0 {
			break
		}
		start := depStart + idx
		endIdx := strings.Index(content[start:], "</dependency>")
		if endIdx < 0 {
			break
		}
		block := content[start : start+endIdx]
		depStart = start + endIdx

		groupID := extractLocalXMLTag(block, "groupId")
		artifactID := extractLocalXMLTag(block, "artifactId")
		version := extractLocalXMLTag(block, "version")
		scopeVal := extractLocalXMLTag(block, "scope")

		// Map Maven scope → canonical scope; compile is production default.
		scope := ScopeProduction
		switch scopeVal {
		case "test":
			scope = ScopeTest
		case "provided":
			scope = ScopeProvided
		case "runtime":
			scope = ScopeRuntime
		case "system":
			scope = ScopeSystem
		}

		if artifactID != "" {
			name := artifactID
			if groupID != "" {
				name = groupID + ":" + artifactID
			}
			pkgs = append(pkgs, ScopedPackage{Name: name, Version: version, Ecosystem: "maven", Scope: scope, SourceFile: filePath, IsDirect: true})
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// PHP / Composer
// ---------------------------------------------------------------------------

type composerLockEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dist    struct {
		Shasum string `json:"shasum"` // hex SHA-1 (or SHA-256) of the dist archive
	} `json:"dist"`
}

func parseComposerLockScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	// composer.lock separates "packages" (production) from "packages-dev" (development).
	var lock struct {
		Packages    []composerLockEntry `json:"packages"`
		PackagesDev []composerLockEntry `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("invalid composer.lock: %w", err)
	}

	var pkgs []ScopedPackage
	add := func(entries []composerLockEntry, scope string) {
		for _, pkg := range entries {
			sp := ScopedPackage{Name: pkg.Name, Version: cleanLocalVersion(pkg.Version), Ecosystem: "composer", Scope: scope, SourceFile: filePath}
			if c := normalizeChecksum(pkg.Dist.Shasum); c.Alg != "" {
				sp.Checksums = []PackageChecksum{c}
			}
			pkgs = append(pkgs, sp)
		}
	}
	add(lock.Packages, ScopeProduction)
	add(lock.PackagesDev, ScopeDevelopment)
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Python — Pipfile (TOML [packages] / [dev-packages])
// ---------------------------------------------------------------------------

// parsePipfileScoped parses a Pipfile TOML, separating [packages] from [dev-packages].
func parsePipfileScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	var pkgs []ScopedPackage
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	currentSection := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			secRaw := strings.Trim(line, "[]")
			switch strings.TrimSpace(secRaw) {
			case "packages":
				currentSection = "prod"
			case "dev-packages":
				currentSection = "dev"
			default:
				currentSection = ""
			}
			continue
		}
		if currentSection == "" || !strings.Contains(line, "=") {
			continue
		}
		idx := strings.Index(line, "=")
		name := strings.TrimSpace(line[:idx])
		rawValue := strings.TrimSpace(line[idx+1:])
		ver := parsePipValue(rawValue)
		versionSpec := parsePipRawSpec(rawValue)
		scope := ScopeProduction
		if currentSection == "dev" {
			scope = ScopeDevelopment
		}
		pkgs = append(pkgs, ScopedPackage{Name: name, Version: ver, VersionSpec: versionSpec, Ecosystem: "pypi", Scope: scope, SourceFile: filePath, IsDirect: true})
	}
	return pkgs, nil
}

func parsePipValue(spec string) string {
	spec = strings.TrimSpace(spec)
	if strings.HasPrefix(spec, "{") {
		for _, q := range []string{`version = "`, "version = '", `version="`} {
			if idx := strings.Index(spec, q); idx >= 0 {
				inner := spec[idx+len(q):]
				if end := strings.Index(inner, `"`); end >= 0 {
					return cleanLocalVersion(inner[:end])
				}
				if end := strings.Index(inner, "'"); end >= 0 {
					return cleanLocalVersion(inner[:end])
				}
			}
		}
		return ""
	}
	return cleanLocalVersion(strings.Trim(spec, `"'`))
}

// parsePipRawSpec extracts the raw version spec (including operator) from a Pipfile
// value string, without cleaning. Used to populate VersionSpec for --block-unpinned.
func parsePipRawSpec(spec string) string {
	spec = strings.TrimSpace(spec)
	if strings.HasPrefix(spec, "{") {
		for _, q := range []string{`version = "`, "version = '", `version="`} {
			if idx := strings.Index(spec, q); idx >= 0 {
				inner := spec[idx+len(q):]
				if end := strings.Index(inner, `"`); end >= 0 {
					return strings.TrimSpace(inner[:end])
				}
				if end := strings.Index(inner, "'"); end >= 0 {
					return strings.TrimSpace(inner[:end])
				}
			}
		}
		return ""
	}
	return strings.Trim(spec, `"'`)
}

// ---------------------------------------------------------------------------
// Python — poetry.lock (TOML [[package]], same as uv.lock)
// ---------------------------------------------------------------------------

// parsePoetryLockScoped parses a poetry.lock file (TOML [[package]] sections).
func parsePoetryLockScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	var pkgs []ScopedPackage
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	var name, version string
	inPackage := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "[[package]]" {
			if inPackage && name != "" {
				pkgs = append(pkgs, ScopedPackage{Name: name, Version: version, Ecosystem: "pypi", Scope: ScopeProduction, SourceFile: filePath})
			}
			name, version = "", ""
			inPackage = true
			continue
		}
		if !inPackage {
			continue
		}
		if strings.HasPrefix(line, "[") && !strings.HasPrefix(line, "[[package]]") {
			if name != "" {
				pkgs = append(pkgs, ScopedPackage{Name: name, Version: version, Ecosystem: "pypi", Scope: ScopeProduction, SourceFile: filePath})
			}
			name, version = "", ""
			inPackage = false
			continue
		}
		if strings.HasPrefix(line, "name = ") {
			name = strings.Trim(strings.TrimPrefix(line, "name = "), `"`)
		}
		if strings.HasPrefix(line, "version = ") {
			version = strings.Trim(strings.TrimPrefix(line, "version = "), `"`)
		}
	}
	if inPackage && name != "" {
		pkgs = append(pkgs, ScopedPackage{Name: name, Version: version, Ecosystem: "pypi", Scope: ScopeProduction, SourceFile: filePath})
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Ruby — Gemfile (Ruby DSL: gem 'name', group :dev)
// ---------------------------------------------------------------------------

func parseGemfileScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	var pkgs []ScopedPackage
	scope := ScopeProduction
	for scanner := bufio.NewScanner(strings.NewReader(string(data))); scanner.Scan(); {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.HasPrefix(line, "group ") && strings.Contains(line, "do") {
			if strings.Contains(line, ":test") {
				scope = ScopeTest
			} else if strings.Contains(line, ":dev") {
				scope = ScopeDevelopment
			}
			continue
		}
		if line == "end" {
			scope = ScopeProduction
			continue
		}
		if m := gemRe.FindSubmatch([]byte(line)); m != nil {
			rawVer := string(m[2])
			ver := cleanLocalVersion(rawVer)
			pkgs = append(pkgs, ScopedPackage{Name: string(m[1]), Version: ver, VersionSpec: rawVer, Ecosystem: "rubygems", Scope: scope, SourceFile: filePath, IsDirect: true})
		}
	}
	return pkgs, nil
}

var gemRe = regexp.MustCompile(`^\s*gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]*)['"])?`)

// ---------------------------------------------------------------------------
// Rust — Cargo.toml (TOML [dependencies], [dev-dependencies], [build-dependencies])
// ---------------------------------------------------------------------------

func parseCargoTomlScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	var pkgs []ScopedPackage
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	section := ""
	scope := ScopeProduction
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			secRaw := strings.Trim(line, "[]")
			switch secRaw {
			case "dependencies":
				section, scope = "deps", ScopeProduction
			case "dev-dependencies":
				section, scope = "deps", ScopeDevelopment
			case "build-dependencies":
				section, scope = "deps", ScopeProduction
			default:
				if strings.HasSuffix(secRaw, ".dependencies") {
					section, scope = "deps", ScopeProduction
				} else {
					section = ""
				}
			}
			continue
		}
		if section != "deps" || !strings.Contains(line, "=") {
			continue
		}
		idx := strings.Index(line, "=")
		name := strings.TrimSpace(line[:idx])
		if name == "" || strings.HasPrefix(name, "#") {
			continue
		}
		rest := strings.TrimSpace(line[idx+1:])
		var ver string
		if strings.HasPrefix(rest, "{") {
			ver = extractInlineVersion(rest)
		} else {
			ver = strings.Trim(rest, `"'`)
		}
		if ver != "" {
			pkgs = append(pkgs, ScopedPackage{Name: name, Version: cleanLocalVersion(ver), VersionSpec: ver, Ecosystem: "cargo", Scope: scope, SourceFile: filePath, IsDirect: true})
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Java / Gradle — build.gradle / build.gradle.kts
// ---------------------------------------------------------------------------

func parseGradleScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	return parseGradleDSL(data, filePath)
}

func parseGradleKtsScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	return parseGradleDSL(data, filePath)
}

func parseGradleDSL(data []byte, filePath string) ([]ScopedPackage, error) {
	var pkgs []ScopedPackage
	cfgScope := func(cfg string) string {
		if strings.HasPrefix(cfg, "test") {
			return ScopeTest
		}
		if strings.Contains(cfg, "compileOnly") || strings.Contains(cfg, "provided") {
			return ScopeProvided
		}
		return ScopeProduction
	}
	for s := bufio.NewScanner(strings.NewReader(string(data))); s.Scan(); {
		line := strings.TrimSpace(s.Text())
		if strings.HasPrefix(line, "//") || line == "" {
			continue
		}
		var cfg, coords string
		if idx := strings.Index(line, "("); idx > 0 {
			cfg = strings.TrimSpace(line[:idx])
			coords = strings.Trim(line[idx:], "()")
			coords = strings.Trim(coords, `"'`)
		} else {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				cfg, coords = parts[0], strings.Trim(strings.Join(parts[1:], " "), `"'`)
			}
		}
		if cfg == "" || coords == "" {
			continue
		}
		if strings.HasPrefix(coords, "libs.") || strings.HasPrefix(coords, "project(") {
			continue
		}
		scope := cfgScope(cfg)
		parts := strings.Split(coords, ":")
		if len(parts) >= 2 {
			ver := ""
			if len(parts) >= 3 {
				ver = parts[2]
			}
			pkgs = append(pkgs, ScopedPackage{Name: parts[0] + ":" + parts[1], Version: cleanLocalVersion(ver), Ecosystem: "maven", Scope: scope, SourceFile: filePath, IsDirect: true})
		}
	}
	return pkgs, nil
}

func parseGradleLockfileScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	var pkgs []ScopedPackage
	for s := bufio.NewScanner(strings.NewReader(string(data))); s.Scan(); {
		line := strings.TrimSpace(s.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		// Each line is "group:artifact:version=config1,config2,…". The part before
		// "=" is the coordinate; the part after is the list of configurations the
		// dependency appears in (discarded). Earlier code split on "=", which put the
		// version into the name and the configuration into the version.
		coord := line
		if idx := strings.IndexByte(coord, '='); idx >= 0 {
			coord = coord[:idx]
		}
		parts := strings.Split(coord, ":")
		if len(parts) < 3 || parts[0] == "" || parts[1] == "" {
			continue // e.g. the trailing "empty=" marker line
		}
		ver := parts[len(parts)-1]
		name := strings.Join(parts[:len(parts)-1], ":") // group:artifact
		pkgs = append(pkgs, ScopedPackage{Name: name, Version: cleanLocalVersion(ver), Ecosystem: "maven", Scope: ScopeProduction, SourceFile: filePath})
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// PHP — composer.json (JSON require / require-dev)
// ---------------------------------------------------------------------------

func parseComposerJSONScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	var pkg struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("invalid composer.json: %w", err)
	}
	var pkgs []ScopedPackage
	for name, ver := range pkg.Require {
		if name == "php" {
			continue
		}
		pkgs = append(pkgs, ScopedPackage{Name: name, Version: cleanLocalVersion(ver), VersionSpec: ver, Ecosystem: "composer", Scope: ScopeProduction, SourceFile: filePath, IsDirect: true})
	}
	for name, ver := range pkg.RequireDev {
		if name == "php" {
			continue
		}
		pkgs = append(pkgs, ScopedPackage{Name: name, Version: cleanLocalVersion(ver), VersionSpec: ver, Ecosystem: "composer", Scope: ScopeDevelopment, SourceFile: filePath, IsDirect: true})
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// .NET / NuGet — packages.lock.json
// ---------------------------------------------------------------------------

// nugetLockFile models the real packages.lock.json schema: a per-target-framework
// map of package id → {type, resolved, contentHash, dependencies}. (The earlier
// parser read a "libraries" key that only exists in project.assets.json, so it
// returned zero packages for every real lock file.)
type nugetLockFile struct {
	Dependencies map[string]map[string]nugetLockEntry `json:"dependencies"`
}

type nugetLockEntry struct {
	Type         string            `json:"type"`     // "Direct" | "Transitive" | "Project" | "CentralTransitive"
	Resolved     string            `json:"resolved"` // exact version
	ContentHash  string            `json:"contentHash"`
	Dependencies map[string]string `json:"dependencies"` // child id → version range
}

func parseNugetLockScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	var lock nugetLockFile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("invalid packages.lock.json: %w", err)
	}
	var pkgs []ScopedPackage
	seen := map[string]bool{}
	for _, byName := range lock.Dependencies {
		for name, entry := range byName {
			if entry.Resolved == "" {
				continue
			}
			key := strings.ToLower(name) + "@" + entry.Resolved
			if seen[key] {
				continue
			}
			seen[key] = true
			sp := ScopedPackage{
				Name: name, Version: entry.Resolved, Ecosystem: "nuget",
				Scope: ScopeProduction, SourceFile: filePath,
				IsDirect: strings.EqualFold(entry.Type, "Direct"),
			}
			if entry.ContentHash != "" {
				// contentHash is a base64-encoded SHA-512; the CDX layer decodes it.
				sp.Checksums = []PackageChecksum{{Alg: "SHA-512", Value: entry.ContentHash}}
			}
			pkgs = append(pkgs, sp)
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// .NET / NuGet — paket.dependencies / paket.lock
// ---------------------------------------------------------------------------

func parsePaketDepsScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	var pkgs []ScopedPackage
	for s := bufio.NewScanner(strings.NewReader(string(data))); s.Scan(); {
		line := strings.TrimSpace(s.Text())
		if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[0] == "nuget" {
			name := parts[1]
			ver := ""
			if len(parts) >= 4 && (parts[2] == "==" || parts[2] == ">=" || parts[2] == "~>") {
				ver = strings.Trim(parts[3], `"`)
			} else if len(parts) >= 3 {
				ver = strings.Trim(parts[2], `"`)
			}
			pkgs = append(pkgs, ScopedPackage{Name: name, Version: ver, Ecosystem: "nuget", Scope: ScopeProduction, SourceFile: filePath, IsDirect: true})
		}
	}
	return pkgs, nil
}

func parsePaketLockScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	var pkgs []ScopedPackage
	inNug := false
	for s := bufio.NewScanner(strings.NewReader(string(data))); s.Scan(); {
		line := s.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "NUGET" {
			inNug = true
			continue
		}
		if inNug && len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			inNug = false
			continue
		}
		if inNug && strings.Contains(trimmed, " (") {
			if idx := strings.Index(trimmed, " ("); idx > 0 {
				pkgs = append(pkgs, ScopedPackage{Name: trimmed[:idx], Version: strings.Trim(trimmed[idx+1:], "()"), Ecosystem: "nuget", Scope: ScopeProduction, SourceFile: filePath})
			}
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// .NET / NuGet — *.csproj (XML PackageReference)
// ---------------------------------------------------------------------------

func parseCsprojScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	var pkgs []ScopedPackage
	content := string(data)
	depStart := 0
	for {
		idx := strings.Index(content[depStart:], "<PackageReference")
		if idx < 0 {
			break
		}
		start := depStart + idx
		endIdx := strings.Index(content[start:], "/>")
		if endIdx < 0 {
			endIdx = strings.Index(content[start:], "</PackageReference>")
			if endIdx < 0 {
				break
			}
		} else {
			endIdx += 2
		}
		block := content[start : start+endIdx]
		depStart = start + endIdx
		include := extractXMLAttr(block, "Include")
		if include == "" {
			include = extractXMLAttr(block, "include")
		}
		version := extractXMLAttr(block, "Version")
		if version == "" {
			version = extractXMLAttr(block, "version")
		}
		if version == "" {
			version = extractLocalXMLTag(block, "Version")
		}
		if version == "" {
			version = extractLocalXMLTag(block, "PackageVersion")
		}
		if include != "" {
			pkgs = append(pkgs, ScopedPackage{Name: include, Version: version, Ecosystem: "nuget", Scope: ScopeProduction, SourceFile: filePath, IsDirect: true})
		}
	}
	return pkgs, nil
}

func extractInlineVersion(s string) string {
	for _, q := range []string{`version = "`, `version="`} {
		if idx := strings.Index(s, q); idx >= 0 {
			inner := s[idx+len(q):]
			if end := strings.Index(inner, `"`); end >= 0 {
				return inner[:end]
			}
		}
	}
	return ""
}

// cleanLocalVersion strips common semver prefix characters.
func cleanLocalVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "==")
	v = strings.TrimPrefix(v, "^")
	v = strings.TrimPrefix(v, "~")
	v = strings.TrimPrefix(v, ">=")
	v = strings.TrimPrefix(v, "v")
	return v
}

// extractLocalXMLTag extracts the text content of an XML tag from a block.
func extractLocalXMLTag(xml, tag string) string {
	open := "<" + tag + ">"
	close := "</" + tag + ">"
	start := strings.Index(xml, open)
	if start < 0 {
		return ""
	}
	start += len(open)
	end := strings.Index(xml[start:], close)
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(xml[start : start+end])
}

func extractXMLAttr(xml, attr string) string {
	prefix := attr + `="`
	start := strings.Index(xml, prefix)
	if start < 0 {
		prefix = attr + `='`
		start = strings.Index(xml, prefix)
	}
	if start < 0 {
		return ""
	}
	start += len(prefix)
	quote := xml[start-1]
	end := strings.IndexByte(xml[start:], quote)
	if end < 0 {
		return ""
	}
	return xml[start : start+end]
}
