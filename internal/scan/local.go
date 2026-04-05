package scan

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
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
	Name       string
	Version    string
	Ecosystem  string
	Scope      string // native scope label (production, development, test, peer, etc.)
	SourceFile string // relative path of the manifest file that declared this package
	IsDirect   bool   // true if declared in the manifest (e.g., go.mod), false if transitive (e.g., go.sum)
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
		pkgs = append(pkgs, ScopedPackage{Name: name, Version: cleanLocalVersion(ver), Ecosystem: "npm", Scope: ScopeProduction, SourceFile: filePath, IsDirect: true})
	}
	for name, ver := range pkg.DevDependencies {
		pkgs = append(pkgs, ScopedPackage{Name: name, Version: cleanLocalVersion(ver), Ecosystem: "npm", Scope: ScopeDevelopment, SourceFile: filePath, IsDirect: true})
	}
	for name, ver := range pkg.PeerDependencies {
		pkgs = append(pkgs, ScopedPackage{Name: name, Version: cleanLocalVersion(ver), Ecosystem: "npm", Scope: ScopePeer, SourceFile: filePath, IsDirect: true})
	}
	for name, ver := range pkg.OptionalDependencies {
		pkgs = append(pkgs, ScopedPackage{Name: name, Version: cleanLocalVersion(ver), Ecosystem: "npm", Scope: ScopeOptional, SourceFile: filePath, IsDirect: true})
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
		var name, version string
		for _, sep := range []string{"==", ">=", "<=", "~=", "!=", ">", "<"} {
			if idx := strings.Index(line, sep); idx > 0 {
				name = strings.TrimSpace(line[:idx])
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
			pkgs = append(pkgs, ScopedPackage{Name: name, Version: version, Ecosystem: "pypi", Scope: ScopeProduction, SourceFile: filePath, IsDirect: true})
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
		secNone         = ""
		secProjectDeps  = "project.dependencies"
		secOptional     = "project.optional-dependencies"
		secDepGroups    = "dependency-groups"
		secUVTool       = "tool.uv"
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
	// Returns name and the raw version specifier; skips group-include dicts.
	extractPyDep := func(raw string) (name, ver string, ok bool) {
		// Strip outer quotes and trailing comma.
		raw = strings.TrimSpace(raw)
		raw = strings.Trim(raw, `"',`)
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "{") || strings.HasPrefix(raw, "#") {
			return "", "", false
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
				return strings.TrimSpace(raw[:idx]), strings.TrimSpace(raw[idx+len(sep):]), true
			}
		}
		// No version specifier — just a bare name.
		if raw != "" {
			return raw, "", true
		}
		return "", "", false
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
			if name, ver, ok := extractPyDep(trimmed); ok {
				isDirect := currentScope == ScopeProduction
				pkgs = append(pkgs, ScopedPackage{
					Name: name, Version: ver,
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
							if n, v, ok := extractPyDep(item); ok {
								pkgs = append(pkgs, ScopedPackage{
									Name: n, Version: v,
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
						if n, v, ok := extractPyDep(item); ok {
							pkgs = append(pkgs, ScopedPackage{
								Name: n, Version: v,
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
						if n, v, ok := extractPyDep(item); ok {
							pkgs = append(pkgs, ScopedPackage{
								Name: n, Version: v,
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
// Helpers
// ---------------------------------------------------------------------------

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
