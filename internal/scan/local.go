package scan

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
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
	Scope       string // native scope label (production, development, test, peer, etc.)
	SourceFile  string // relative path of the manifest file that declared this package
	IsDirect    bool   // true if declared in the manifest (e.g., go.mod), false if transitive (e.g., go.sum)
	GitHubURL   string // optional: "owner/repo" for packages whose VCS is known from the manifest
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
	case "pyproject.toml":
		return parsePyprojectTOMLScoped(data, filePath)
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
	// ── Docker ────────────────────────────────────────────────────────────
	case "Dockerfile":
		return parseDockerfileScoped(data, filePath)
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
		} `json:"packages"`
		Dependencies map[string]struct {
			Version  string `json:"version"`
			Dev      bool   `json:"dev"`
			Optional bool   `json:"optional"`
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
		pkgs = append(pkgs, ScopedPackage{Name: name, Version: pkg.Version, Ecosystem: "npm", Scope: scope, SourceFile: filePath})
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
		pkgs = append(pkgs, ScopedPackage{Name: name, Version: pkg.Version, Ecosystem: "npm", Scope: scope, SourceFile: filePath})
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
	var currentName string

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
			continue
		}

		if currentName == "" {
			continue
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
				pkgs = append(pkgs, ScopedPackage{Name: currentName, Version: version, Ecosystem: "npm", Scope: ScopeProduction, SourceFile: filePath})
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

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "packages:" {
			inPackages = true
			continue
		}
		if inPackages && len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			inPackages = false
			continue
		}

		if inPackages && strings.HasPrefix(trimmed, "/") && strings.Contains(trimmed, "@") {
			entry := strings.TrimPrefix(strings.TrimSuffix(trimmed, ":"), "/")
			lastAt := strings.LastIndex(entry, "@")
			if lastAt > 0 {
				name := entry[:lastAt]
				version := entry[lastAt+1:]
				key := name + "@" + version
				if !seen[key] {
					seen[key] = true
					pkgs = append(pkgs, ScopedPackage{Name: name, Version: version, Ecosystem: "npm", Scope: ScopeProduction, SourceFile: filePath})
				}
			}
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Python
// ---------------------------------------------------------------------------

func parseRequirementsTxtScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	// requirements.txt has no scope concept; all deps are treated as production.
	var pkgs []ScopedPackage
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		var name, version, versionSpec string
		for _, sep := range []string{"==", ">=", "<=", "~=", "!=", ">", "<"} {
			if idx := strings.Index(line, sep); idx > 0 {
				name = strings.TrimSpace(line[:idx])
				rawSpec := strings.TrimSpace(line[idx:]) // includes the operator
				versionSpec = rawSpec
				version = strings.TrimSpace(line[idx+len(sep):])
				if bIdx := strings.Index(name, "["); bIdx > 0 {
					name = name[:bIdx]
				}
				break
			}
		}
		if name == "" {
			name = strings.TrimSpace(line)
			if bIdx := strings.Index(name, "["); bIdx > 0 {
				name = name[:bIdx]
			}
		}
		if name != "" {
			pkgs = append(pkgs, ScopedPackage{Name: name, Version: version, VersionSpec: versionSpec, Ecosystem: "pypi", Scope: ScopeProduction, SourceFile: filePath, IsDirect: true})
		}
	}
	return pkgs, nil
}

func parsePipfileLockScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	// Pipfile.lock separates [default] (production) from [develop] (development).
	var lock struct {
		Default map[string]struct {
			Version string `json:"version"`
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
		} `json:"develop"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("invalid Pipfile.lock: %w", err)
	}

	var pkgs []ScopedPackage
	for name, pkg := range lock.Default {
		pkgs = append(pkgs, ScopedPackage{Name: name, Version: cleanLocalVersion(pkg.Version), Ecosystem: "pypi", Scope: ScopeProduction, SourceFile: filePath})
	}
	for name, pkg := range lock.Develop {
		pkgs = append(pkgs, ScopedPackage{Name: name, Version: cleanLocalVersion(pkg.Version), Ecosystem: "pypi", Scope: ScopeDevelopment, SourceFile: filePath})
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Python (uv.lock + pyproject.toml)
// ---------------------------------------------------------------------------

// parseUVLockScoped parses a uv.lock file (TOML, [[package]] sections).
// uv.lock does not encode production/dev scope per-package; all packages are
// marked as production. Scope correlation would require pairing with pyproject.toml.
func parseUVLockScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	var pkgs []ScopedPackage
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	var name, version string
	inPackage := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "[[package]]" {
			if inPackage && name != "" {
				pkgs = append(pkgs, ScopedPackage{
					Name: name, Version: version,
					Ecosystem: "pypi", Scope: ScopeProduction,
					SourceFile: filePath,
				})
			}
			name, version = "", ""
			inPackage = true
			continue
		}
		if !inPackage {
			continue
		}
		// A new top-level section (non-indented "[") that is not "[[package]]" ends the current block.
		if strings.HasPrefix(line, "[") && !strings.HasPrefix(line, "[[package]]") {
			if name != "" {
				pkgs = append(pkgs, ScopedPackage{
					Name: name, Version: version,
					Ecosystem: "pypi", Scope: ScopeProduction,
					SourceFile: filePath,
				})
				name, version = "", ""
			}
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
	// Flush the last package block.
	if inPackage && name != "" {
		pkgs = append(pkgs, ScopedPackage{
			Name: name, Version: version,
			Ecosystem: "pypi", Scope: ScopeProduction,
			SourceFile: filePath,
		})
	}
	return pkgs, nil
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

	// extractPyDep parses a PEP 508 dependency specifier string (e.g. "PyYAML>=6.0").
	// Returns name, cleaned version, full version spec (operator+version), and ok.
	// Skips group-include dicts.
	extractPyDep := func(raw string) (name, ver, versionSpec string, ok bool) {
		// Strip outer quotes and trailing comma.
		raw = strings.TrimSpace(raw)
		raw = strings.Trim(raw, `"',`)
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "{") || strings.HasPrefix(raw, "#") {
			return "", "", "", false
		}
		// Strip any environment markers ("pkg>=1.0 ; python_version>='3.8'").
		if idx := strings.Index(raw, ";"); idx > 0 {
			raw = strings.TrimSpace(raw[:idx])
		}
		// Strip extras ("pkg[extra]>=1.0").
		if bIdx := strings.Index(raw, "["); bIdx > 0 {
			if eIdx := strings.Index(raw, "]"); eIdx > bIdx {
				raw = raw[:bIdx] + raw[eIdx+1:]
			}
		}
		for _, sep := range []string{"==", ">=", "<=", "~=", "!=", ">", "<"} {
			if idx := strings.Index(raw, sep); idx > 0 {
				return strings.TrimSpace(raw[:idx]), strings.TrimSpace(raw[idx+len(sep):]), strings.TrimSpace(raw[idx:]), true
			}
		}
		// No version specifier — just a bare name.
		if raw != "" {
			return raw, "", "", true
		}
		return "", "", "", false
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
		if len(parts) < 2 {
			continue
		}
		name := parts[0]
		version := strings.TrimSuffix(parts[1], "/go.mod")
		version = strings.TrimPrefix(version, "v")
		key := name + "@" + version
		if !seen[key] {
			seen[key] = true
			pkgs = append(pkgs, ScopedPackage{Name: name, Version: version, Ecosystem: "golang", Scope: ScopeProduction, SourceFile: filePath, IsDirect: false})
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
	var name, version string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "[[package]]" {
			if name != "" {
				pkgs = append(pkgs, ScopedPackage{Name: name, Version: version, Ecosystem: "cargo", Scope: ScopeProduction, SourceFile: filePath})
			}
			name, version = "", ""
			continue
		}
		if strings.HasPrefix(line, "name = ") {
			name = strings.Trim(strings.TrimPrefix(line, "name = "), "\"")
		}
		if strings.HasPrefix(line, "version = ") {
			version = strings.Trim(strings.TrimPrefix(line, "version = "), "\"")
		}
	}
	if name != "" {
		pkgs = append(pkgs, ScopedPackage{Name: name, Version: version, Ecosystem: "cargo", Scope: ScopeProduction, SourceFile: filePath})
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Ruby
// ---------------------------------------------------------------------------

func parseGemfileLockScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	// Gemfile.lock lists all specs; group info comes from Gemfile which isn't parsed here.
	var pkgs []ScopedPackage
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	inSpecs := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "specs:" {
			inSpecs = true
			continue
		}
		if inSpecs && len(line) > 0 && line[0] != ' ' {
			inSpecs = false
			continue
		}
		if inSpecs {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				name := parts[0]
				version := strings.Trim(parts[1], "()")
				pkgs = append(pkgs, ScopedPackage{Name: name, Version: version, Ecosystem: "gem", Scope: ScopeProduction, SourceFile: filePath})
			}
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

func parseComposerLockScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	// composer.lock separates "packages" (production) from "packages-dev" (development).
	var lock struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
		PackagesDev []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("invalid composer.lock: %w", err)
	}

	var pkgs []ScopedPackage
	for _, pkg := range lock.Packages {
		pkgs = append(pkgs, ScopedPackage{Name: pkg.Name, Version: cleanLocalVersion(pkg.Version), Ecosystem: "composer", Scope: ScopeProduction, SourceFile: filePath})
	}
	for _, pkg := range lock.PackagesDev {
		pkgs = append(pkgs, ScopedPackage{Name: pkg.Name, Version: cleanLocalVersion(pkg.Version), Ecosystem: "composer", Scope: ScopeDevelopment, SourceFile: filePath})
	}
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
		if idx := strings.Index(line, "="); idx > 0 {
			coord := line[:idx]
			ver := strings.TrimSpace(line[idx+1:])
			pkgs = append(pkgs, ScopedPackage{Name: coord, Version: ver, Ecosystem: "maven", Scope: ScopeProduction, SourceFile: filePath})
		}
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

func parseNugetLockScoped(data []byte, filePath string) ([]ScopedPackage, error) {
	var lock struct {
		Libraries map[string]struct {
			Resolved string `json:"resolved"`
		} `json:"libraries"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("invalid packages.lock.json: %w", err)
	}
	var pkgs []ScopedPackage
	for name, pkg := range lock.Libraries {
		pkgs = append(pkgs, ScopedPackage{Name: name, Version: pkg.Resolved, Ecosystem: "nuget", Scope: ScopeProduction, SourceFile: filePath})
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
