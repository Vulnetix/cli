package scan

// local_extra.go contains parsers for the extended set of package manager
// manifest / lock file formats supported by Vulnetix.  Every function follows
// the same signature as the parsers in local.go:
//
//	func parseXxxScoped(data []byte, filePath string) ([]ScopedPackage, error)
//
// All parsers are deliberately lenient: malformed lines are skipped rather
// than returned as errors, so a partially-valid file still yields useful data.

import (
	"bufio"
	"encoding/json"
	"regexp"
	"strings"
)

// ---------------------------------------------------------------------------
// Swift — Package.swift (SPM)
// ---------------------------------------------------------------------------

// parsePackageSwiftScoped extracts .package(url: "…", from: "…") declarations.
func parsePackageSwiftScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// Matches:  .package(url: "https://github.com/foo/bar.git", from: "1.2.3")
	// or:       .package(url: "…", .upToNextMajor(from: "1.2.3"))
	// or:       .package(url: "…", branch: "main")
	urlRe := regexp.MustCompile(`\.package\(\s*url\s*:\s*"([^"]+)"`)
	fromRe := regexp.MustCompile(`from\s*:\s*"([^"]+)"`)
	exactRe := regexp.MustCompile(`exact\s*:\s*"([^"]+)"`)

	var pkgs []ScopedPackage
	content := string(data)
	for _, line := range strings.Split(content, "\n") {
		urlM := urlRe.FindStringSubmatch(line)
		if urlM == nil {
			continue
		}
		rawURL := urlM[1]
		// Derive a package name from the URL (last path component, strip .git).
		name := rawURL
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
		name = strings.TrimSuffix(name, ".git")

		ver := ""
		if m := fromRe.FindStringSubmatch(line); m != nil {
			ver = m[1]
		} else if m := exactRe.FindStringSubmatch(line); m != nil {
			ver = m[1]
		}
		if name != "" {
			pkgs = append(pkgs, ScopedPackage{
				Name: name, Version: ver,
				Ecosystem: "swift", Scope: ScopeProduction, IsDirect: true,
			})
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Swift — Package.resolved (JSON v1/v2/v3)
// ---------------------------------------------------------------------------

func parsePackageResolvedScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// v1: {"object":{"pins":[{"package":"…","state":{"version":"…"}}]}}
	// v2: {"pins":[{"identity":"…","state":{"version":"…"}}]}
	// v3: same as v2

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil //nolint:nilerr
	}

	type pin struct {
		Package  string `json:"package"`
		Identity string `json:"identity"`
		State    struct {
			Version  string `json:"version"`
			Branch   string `json:"branch"`
			Revision string `json:"revision"`
		} `json:"state"`
	}
	type v1Wrapper struct {
		Object struct {
			Pins []pin `json:"pins"`
		} `json:"object"`
	}
	type v2Wrapper struct {
		Pins []pin `json:"pins"`
	}

	// Try v2/v3 first.
	var v2 v2Wrapper
	if err := json.Unmarshal(data, &v2); err == nil && len(v2.Pins) > 0 {
		var pkgs []ScopedPackage
		for _, p := range v2.Pins {
			name := p.Identity
			if name == "" {
				name = p.Package
			}
			ver := p.State.Version
			if ver == "" {
				ver = p.State.Branch
			}
			if name != "" {
				pkgs = append(pkgs, ScopedPackage{Name: name, Version: ver, Ecosystem: "swift", Scope: ScopeProduction})
			}
		}
		return pkgs, nil
	}
	// Try v1.
	var v1 v1Wrapper
	if err := json.Unmarshal(data, &v1); err == nil && len(v1.Object.Pins) > 0 {
		var pkgs []ScopedPackage
		for _, p := range v1.Object.Pins {
			name := p.Package
			if name == "" {
				name = p.Identity
			}
			ver := p.State.Version
			if ver == "" {
				ver = p.State.Branch
			}
			if name != "" {
				pkgs = append(pkgs, ScopedPackage{Name: name, Version: ver, Ecosystem: "swift", Scope: ScopeProduction})
			}
		}
		return pkgs, nil
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// Dart / Flutter — pubspec.yaml
// ---------------------------------------------------------------------------

func parsePubspecYAMLScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// Manual line-by-line parse; avoids a YAML library dependency.
	// [dependencies] → production   [dev_dependencies] → development
	var pkgs []ScopedPackage
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	const (
		secNone = ""
		secProd = "prod"
		secDev  = "dev"
	)
	section := secNone

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}

		// Top-level section headers (no leading spaces).
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			switch {
			case strings.HasPrefix(trimmed, "dependencies:"):
				section = secProd
			case strings.HasPrefix(trimmed, "dev_dependencies:"):
				section = secDev
			default:
				section = secNone
			}
			continue
		}

		if section == secNone {
			continue
		}

		// Indented entry:  "  package: ^1.2.3"  or  "  package:"
		if idx := strings.Index(trimmed, ":"); idx > 0 {
			name := strings.TrimSpace(trimmed[:idx])
			ver := strings.TrimSpace(trimmed[idx+1:])
			ver = cleanLocalVersion(ver)
			scope := ScopeProduction
			if section == secDev {
				scope = ScopeDevelopment
			}
			pkgs = append(pkgs, ScopedPackage{Name: name, Version: ver, Ecosystem: "pub", Scope: scope, IsDirect: true})
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Dart / Flutter — pubspec.lock
// ---------------------------------------------------------------------------

func parsePubspecLockScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// pubspec.lock is YAML; we parse it line-by-line.
	// Structure:
	//   packages:
	//     pkg_name:
	//       dependency: "direct main" | "direct dev" | "transitive"
	//       version: "1.2.3"
	var pkgs []ScopedPackage
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	var currentName, currentDep, currentVer string
	inPackages := false
	inEntry := false

	flush := func() {
		if currentName == "" {
			return
		}
		scope := ScopeProduction
		if strings.Contains(currentDep, "dev") {
			scope = ScopeDevelopment
		}
		isDirect := strings.HasPrefix(currentDep, "direct")
		pkgs = append(pkgs, ScopedPackage{
			Name: currentName, Version: currentVer,
			Ecosystem: "pub", Scope: scope, IsDirect: isDirect,
		})
		currentName, currentDep, currentVer = "", "", ""
	}

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}

		// Count leading spaces to track nesting.
		indent := len(line) - len(strings.TrimLeft(line, " \t"))

		if trimmed == "packages:" && indent == 0 {
			inPackages = true
			continue
		}
		if !inPackages {
			continue
		}

		// Package name is at indent 2.
		if indent == 2 && strings.HasSuffix(trimmed, ":") {
			flush()
			currentName = strings.TrimSuffix(trimmed, ":")
			inEntry = true
			continue
		}

		if !inEntry || indent <= 2 {
			continue
		}

		if strings.HasPrefix(trimmed, "dependency:") {
			currentDep = strings.TrimSpace(strings.TrimPrefix(trimmed, "dependency:"))
			currentDep = strings.Trim(currentDep, `"'`)
		}
		if strings.HasPrefix(trimmed, "version:") {
			currentVer = strings.TrimSpace(strings.TrimPrefix(trimmed, "version:"))
			currentVer = strings.Trim(currentVer, `"'`)
		}
	}
	flush()
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Elixir — mix.exs
// ---------------------------------------------------------------------------

// parseMixScoped extracts {:dep_name, "~> 1.2"} entries from deps/0.
func parseMixScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// Match:  {:some_dep, "~> 1.2.3"}  or  {:dep, git: "…", tag: "v1.0"}
	depRe := regexp.MustCompile(`\{:([a-z_][a-zA-Z0-9_]*)\s*,\s*"([^"]*)"`)
	var pkgs []ScopedPackage
	for _, line := range strings.Split(string(data), "\n") {
		m := depRe.FindStringSubmatch(line)
		if m != nil {
			pkgs = append(pkgs, ScopedPackage{
				Name: m[1], Version: cleanLocalVersion(m[2]),
				Ecosystem: "hex", Scope: ScopeProduction, IsDirect: true,
			})
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Elixir — mix.lock
// ---------------------------------------------------------------------------

// parseMixLockScoped extracts packages from mix.lock.
// Format:  "pkg_name": {:hex, :pkg_atom, "1.2.3", …}
func parseMixLockScoped(data []byte, _ string) ([]ScopedPackage, error) {
	lineRe := regexp.MustCompile(`^\s*"([^"]+)"\s*:\s*\{:hex\s*,\s*:[a-z_]+\s*,\s*"([^"]+)"`)
	var pkgs []ScopedPackage
	for _, line := range strings.Split(string(data), "\n") {
		m := lineRe.FindStringSubmatch(line)
		if m != nil {
			pkgs = append(pkgs, ScopedPackage{
				Name: m[1], Version: m[2],
				Ecosystem: "hex", Scope: ScopeProduction,
			})
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Scala / sbt — build.sbt
// ---------------------------------------------------------------------------

// parseBuildSbtScoped extracts "group" % "artifact" % "version" declarations.
func parseBuildSbtScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// Matches:  "org.foo" % "bar" % "1.2.3"  (Scala-style)  or  "org.foo" %% "bar" % "1.2.3"
	depRe := regexp.MustCompile(`"([^"]+)"\s*%%?\s*"([^"]+)"\s*%%?\s*"([^"]+)"`)
	var pkgs []ScopedPackage
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		m := depRe.FindStringSubmatch(line)
		if m != nil {
			scope := ScopeProduction
			if strings.Contains(line, `% "test"`) || strings.Contains(line, `% Test`) {
				scope = ScopeTest
			}
			pkgs = append(pkgs, ScopedPackage{
				Name: m[1] + ":" + m[2], Version: m[3],
				Ecosystem: "maven", Scope: scope, IsDirect: true,
			})
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Scala / sbt — build.lock (sbt lock-file plugin)
// ---------------------------------------------------------------------------

func parseBuildLockScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// Format (sbt-lock): org:name:version=…  or  group:artifact:version
	var pkgs []ScopedPackage
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		coord := parts[0]
		fields := strings.Split(coord, ":")
		if len(fields) >= 3 {
			pkgs = append(pkgs, ScopedPackage{
				Name: fields[0] + ":" + fields[1], Version: fields[2],
				Ecosystem: "maven", Scope: ScopeProduction,
			})
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Docker — Dockerfile
// ---------------------------------------------------------------------------

// parseDockerfileScoped extracts base images from FROM instructions.
func parseDockerfileScoped(data []byte, _ string) ([]ScopedPackage, error) {
	var pkgs []ScopedPackage
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToUpper(trimmed), "FROM ") {
			continue
		}
		ref := strings.TrimSpace(trimmed[5:])
		// Strip optional AS alias.
		if idx := strings.Index(strings.ToUpper(ref), " AS "); idx > 0 {
			ref = strings.TrimSpace(ref[:idx])
		}
		if ref == "scratch" {
			continue
		}
		name, ver := splitDockerRef(ref)
		pkgs = append(pkgs, ScopedPackage{
			Name: name, Version: ver,
			Ecosystem: "docker", Scope: ScopeProduction, IsDirect: true,
		})
	}
	return pkgs, nil
}

func splitDockerRef(ref string) (name, ver string) {
	// ref may be:  ubuntu:22.04  or  ubuntu@sha256:…  or  myimage
	if idx := strings.LastIndex(ref, ":"); idx > 0 {
		return ref[:idx], ref[idx+1:]
	}
	if idx := strings.Index(ref, "@"); idx > 0 {
		return ref[:idx], ref[idx+1:]
	}
	return ref, ""
}

// ---------------------------------------------------------------------------
// GitHub Actions — .github/workflows/*.yml
// ---------------------------------------------------------------------------

// parseGithubActionsScoped extracts `uses: owner/repo@ref` from workflow files.
func parseGithubActionsScoped(data []byte, _ string) ([]ScopedPackage, error) {
	usesRe := regexp.MustCompile(`uses\s*:\s*([^#\s]+)`)
	var pkgs []ScopedPackage
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		m := usesRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		ref := strings.TrimSpace(m[1])
		// Strip local path references.
		if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "../") {
			continue
		}
		name, ver := splitAtSign(ref)
		key := name + "@" + ver
		if !seen[key] {
			seen[key] = true
			pkgs = append(pkgs, ScopedPackage{
				Name: name, Version: ver,
				Ecosystem: "github-actions", Scope: ScopeProduction, IsDirect: true,
			})
		}
	}
	return pkgs, nil
}

func splitAtSign(ref string) (name, ver string) {
	idx := strings.LastIndex(ref, "@")
	if idx > 0 {
		return ref[:idx], ref[idx+1:]
	}
	return ref, ""
}

// ---------------------------------------------------------------------------
// Terraform — *.tf (HCL provider / module blocks)
// ---------------------------------------------------------------------------

// parseTerraformScoped extracts provider and module source/version declarations.
func parseTerraformScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// Look for:
	//   required_providers { name = { source = "…" version = "…" } }
	//   module "name" { source = "…" version = "…" }
	var pkgs []ScopedPackage
	content := string(data)

	sourceRe := regexp.MustCompile(`source\s*=\s*"([^"]+)"`)
	versionRe := regexp.MustCompile(`version\s*=\s*"([^"]+)"`)

	// Split on blocks naively.
	blocks := strings.Split(content, "}")
	for _, block := range blocks {
		sourceM := sourceRe.FindStringSubmatch(block)
		if sourceM == nil {
			continue
		}
		src := sourceM[1]
		ver := ""
		if m := versionRe.FindStringSubmatch(block); m != nil {
			ver = cleanLocalVersion(m[1])
		}
		// Derive a short name from the source address (last component).
		name := src
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
		pkgs = append(pkgs, ScopedPackage{
			Name: src, Version: ver,
			Ecosystem: "terraform", Scope: ScopeProduction, IsDirect: true,
		})
		_ = name
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// C/C++ — conanfile.txt
// ---------------------------------------------------------------------------

func parseConanfileScoped(data []byte, _ string) ([]ScopedPackage, error) {
	var pkgs []ScopedPackage
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	inRequires := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.EqualFold(line, "[requires]") {
			inRequires = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			inRequires = false
			continue
		}
		if !inRequires || line == "" {
			continue
		}
		// Format: name/version  or  name/version@user/channel
		spec := strings.Split(line, "@")[0]
		if idx := strings.Index(spec, "/"); idx > 0 {
			pkgs = append(pkgs, ScopedPackage{
				Name: spec[:idx], Version: spec[idx+1:],
				Ecosystem: "conan", Scope: ScopeProduction, IsDirect: true,
			})
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// C/C++ — conan.lock (JSON)
// ---------------------------------------------------------------------------

func parseConanLockScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// conan.lock JSON structure:
	//   { "graph_lock": { "nodes": { "1": { "ref": "name/version#…", … }, … } } }
	var raw struct {
		GraphLock struct {
			Nodes map[string]struct {
				Ref string `json:"ref"`
			} `json:"nodes"`
		} `json:"graph_lock"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil //nolint:nilerr
	}
	var pkgs []ScopedPackage
	for _, node := range raw.GraphLock.Nodes {
		ref := node.Ref
		// Strip revision hash if present.
		if idx := strings.Index(ref, "#"); idx > 0 {
			ref = ref[:idx]
		}
		if idx := strings.Index(ref, "/"); idx > 0 {
			pkgs = append(pkgs, ScopedPackage{
				Name: ref[:idx], Version: ref[idx+1:],
				Ecosystem: "conan", Scope: ScopeProduction,
			})
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// C/C++ — vcpkg.json
// ---------------------------------------------------------------------------

func parseVcpkgJSONScoped(data []byte, _ string) ([]ScopedPackage, error) {
	var manifest struct {
		Dependencies []json.RawMessage `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, nil //nolint:nilerr
	}
	var pkgs []ScopedPackage
	for _, raw := range manifest.Dependencies {
		// Each entry is either a string "name" or an object {"name":"…","version-minimum":"…"}.
		var name string
		var ver string
		if err := json.Unmarshal(raw, &name); err == nil {
			// Simple string form.
		} else {
			var obj struct {
				Name    string `json:"name"`
				Version string `json:"version-minimum"`
			}
			if err := json.Unmarshal(raw, &obj); err == nil {
				name = obj.Name
				ver = obj.Version
			}
		}
		if name != "" {
			pkgs = append(pkgs, ScopedPackage{
				Name: name, Version: ver,
				Ecosystem: "vcpkg", Scope: ScopeProduction, IsDirect: true,
			})
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// CocoaPods — Podfile (Ruby DSL)
// ---------------------------------------------------------------------------

func parsePodfileScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// Matches:  pod 'AFNetworking', '~> 4.0'
	podRe := regexp.MustCompile(`^\s*pod\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]*)['"])?`)
	var pkgs []ScopedPackage
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		m := podRe.FindStringSubmatch(line)
		if m != nil {
			pkgs = append(pkgs, ScopedPackage{
				Name: m[1], Version: cleanLocalVersion(m[2]),
				Ecosystem: "cocoapods", Scope: ScopeProduction, IsDirect: true,
			})
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// CocoaPods — Podfile.lock
// ---------------------------------------------------------------------------

func parsePodfileLockScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// PODS section lists resolved versions:
	//   PODS:
	//     - AFNetworking (4.0.1)
	//     - AFNetworking/NSURLSession (4.0.1)
	var pkgs []ScopedPackage
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	inPods := false
	seen := map[string]bool{}
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "PODS:" {
			inPods = true
			continue
		}
		if inPods && len(line) > 0 && line[0] != ' ' {
			inPods = false
			continue
		}
		if !inPods {
			continue
		}
		entry := strings.TrimPrefix(trimmed, "- ")
		if idx := strings.Index(entry, " ("); idx > 0 {
			name := entry[:idx]
			// Skip subspecs (those with /).
			if strings.Contains(name, "/") {
				continue
			}
			ver := strings.Trim(entry[idx+1:], "()")
			if !seen[name] {
				seen[name] = true
				pkgs = append(pkgs, ScopedPackage{
					Name: name, Version: ver,
					Ecosystem: "cocoapods", Scope: ScopeProduction,
				})
			}
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Carthage — Cartfile
// ---------------------------------------------------------------------------

// parseCartfileScoped extracts github / git / binary dependencies.
func parseCartfileScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// Format: github "owner/repo" "~> 1.0"  |  binary "…" "1.0"
	re := regexp.MustCompile(`^(?:github|git|binary)\s+"([^"]+)"\s*(?:"([^"]*)")?`)
	var pkgs []ScopedPackage
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		m := re.FindStringSubmatch(line)
		if m != nil {
			name := m[1]
			// For github references, strip owner prefix.
			if strings.Contains(name, "/") {
				parts := strings.SplitN(name, "/", 2)
				name = parts[1]
			}
			pkgs = append(pkgs, ScopedPackage{
				Name: name, Version: cleanLocalVersion(m[2]),
				Ecosystem: "carthage", Scope: ScopeProduction, IsDirect: true,
			})
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Carthage — Cartfile.resolved
// ---------------------------------------------------------------------------

func parseCartfileResolvedScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// Format: github "owner/repo" "1.0.0"
	re := regexp.MustCompile(`^(?:github|git|binary)\s+"([^"]+)"\s+"([^"]+)"`)
	var pkgs []ScopedPackage
	for _, line := range strings.Split(string(data), "\n") {
		m := re.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		name := m[1]
		if strings.Contains(name, "/") {
			parts := strings.SplitN(name, "/", 2)
			name = parts[1]
		}
		pkgs = append(pkgs, ScopedPackage{
			Name: name, Version: m[2],
			Ecosystem: "carthage", Scope: ScopeProduction,
		})
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Julia — Project.toml
// ---------------------------------------------------------------------------

func parseProjectTomlScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// [deps] section:  PackageName = "uuid"
	// [compat] section provides version constraints.
	var pkgs []ScopedPackage
	depsSection := false
	compatSection := false
	compat := map[string]string{}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			sec := strings.Trim(line, "[]")
			depsSection = sec == "deps"
			compatSection = sec == "compat"
			continue
		}
		if compatSection {
			if idx := strings.Index(line, "="); idx > 0 {
				name := strings.TrimSpace(line[:idx])
				ver := strings.Trim(strings.TrimSpace(line[idx+1:]), `"`)
				compat[name] = ver
			}
			continue
		}
		if depsSection {
			if idx := strings.Index(line, "="); idx > 0 {
				name := strings.TrimSpace(line[:idx])
				pkgs = append(pkgs, ScopedPackage{Name: name, Ecosystem: "julia", Scope: ScopeProduction, IsDirect: true})
			}
		}
	}
	// Apply compat versions.
	for i, p := range pkgs {
		if v, ok := compat[p.Name]; ok {
			pkgs[i].Version = v
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Julia — Manifest.toml
// ---------------------------------------------------------------------------

func parseManifestTomlScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// [[deps.PackageName]]  or  [deps.PackageName]  blocks contain:
	//   uuid = "…"  and  version = "…"
	var pkgs []ScopedPackage
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	var currentName, currentVer string

	flush := func() {
		if currentName != "" {
			pkgs = append(pkgs, ScopedPackage{
				Name: currentName, Version: currentVer,
				Ecosystem: "julia", Scope: ScopeProduction,
			})
		}
		currentName, currentVer = "", ""
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.HasPrefix(line, "[[deps.") || strings.HasPrefix(line, "[deps.") {
			flush()
			sec := strings.TrimLeft(line, "[")
			sec = strings.TrimRight(sec, "]")
			currentName = strings.TrimPrefix(sec, "deps.")
			continue
		}
		if strings.HasPrefix(line, "version = ") {
			currentVer = strings.Trim(strings.TrimPrefix(line, "version = "), `"`)
		}
	}
	flush()
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Crystal — shard.yml
// ---------------------------------------------------------------------------

func parseShardYAMLScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// dependencies:
	//   shard_name:
	//     version: "~> 1.0"
	var pkgs []ScopedPackage
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	const (
		secNone = 0
		secProd = 1
		secDev  = 2
	)
	section := secNone
	var currentName string

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if indent == 0 {
			switch {
			case strings.HasPrefix(trimmed, "dependencies:"):
				section = secProd
			case strings.HasPrefix(trimmed, "development_dependencies:"):
				section = secDev
			default:
				section = secNone
			}
			currentName = ""
			continue
		}
		if section == secNone {
			continue
		}
		if indent == 2 && strings.HasSuffix(trimmed, ":") {
			currentName = strings.TrimSuffix(trimmed, ":")
			continue
		}
		if indent > 2 && currentName != "" && strings.HasPrefix(trimmed, "version:") {
			ver := cleanLocalVersion(strings.TrimSpace(strings.TrimPrefix(trimmed, "version:")))
			scope := ScopeProduction
			if section == secDev {
				scope = ScopeDevelopment
			}
			pkgs = append(pkgs, ScopedPackage{Name: currentName, Version: ver, Ecosystem: "crystal", Scope: scope, IsDirect: true})
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Crystal — shard.lock
// ---------------------------------------------------------------------------

func parseShardLockScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// Format:
	//   shards:
	//     shard_name:
	//       version: 1.0.0
	var pkgs []ScopedPackage
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	inShards := false
	var currentName string

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " \t"))

		if trimmed == "shards:" {
			inShards = true
			continue
		}
		if !inShards {
			continue
		}
		if indent == 2 && strings.HasSuffix(trimmed, ":") {
			currentName = strings.TrimSuffix(trimmed, ":")
			continue
		}
		if indent > 2 && currentName != "" && strings.HasPrefix(trimmed, "version:") {
			ver := strings.TrimSpace(strings.TrimPrefix(trimmed, "version:"))
			pkgs = append(pkgs, ScopedPackage{Name: currentName, Version: ver, Ecosystem: "crystal", Scope: ScopeProduction})
			currentName = ""
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Deno — deno.json (importMap / imports)
// ---------------------------------------------------------------------------

func parseDenoJSONScoped(data []byte, _ string) ([]ScopedPackage, error) {
	var manifest struct {
		Imports map[string]string `json:"imports"`
		// deno.json may also nest under importMap pointing to a file, which we skip.
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, nil //nolint:nilerr
	}
	var pkgs []ScopedPackage
	for specifier, resolved := range manifest.Imports {
		name, ver := parseDenoSpecifier(specifier, resolved)
		if name != "" {
			pkgs = append(pkgs, ScopedPackage{Name: name, Version: ver, Ecosystem: "deno", Scope: ScopeProduction, IsDirect: true})
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Deno — deno.lock (JSON v2/v3)
// ---------------------------------------------------------------------------

func parseDenoLockScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// v2/v3 format: { "remote": { "url": "hash" }, "packages": { "specifiers": { "npm:foo@1": "…" } } }
	var lock struct {
		Packages struct {
			Specifiers map[string]string `json:"specifiers"`
		} `json:"packages"`
		// v1 remote map (fallback)
		Remote map[string]string `json:"remote"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, nil //nolint:nilerr
	}
	var pkgs []ScopedPackage
	for spec, resolved := range lock.Packages.Specifiers {
		name, ver := parseDenoSpecifier(spec, resolved)
		if name != "" {
			pkgs = append(pkgs, ScopedPackage{Name: name, Version: ver, Ecosystem: "deno", Scope: ScopeProduction})
		}
	}
	return pkgs, nil
}

// parseDenoSpecifier extracts a name and version from a Deno import specifier.
// e.g. "npm:lodash@4.17.21" → ("lodash", "4.17.21")
//
//	"https://deno.land/x/oak@v12.0.0/mod.ts" → ("oak", "v12.0.0")
func parseDenoSpecifier(specifier, _ string) (name, ver string) {
	// npm specifier: npm:pkg@1.2.3
	if strings.HasPrefix(specifier, "npm:") {
		s := strings.TrimPrefix(specifier, "npm:")
		name, ver = splitAtSign(s)
		if name == "" {
			name = s
		}
		return
	}
	// deno.land/x: https://deno.land/x/pkg@v1.0/mod.ts
	if strings.Contains(specifier, "deno.land/x/") {
		rest := specifier[strings.Index(specifier, "deno.land/x/")+len("deno.land/x/"):]
		rest = strings.Split(rest, "/")[0] // stop at next /
		name, ver = splitAtSign(rest)
		if name == "" {
			name = rest
		}
		return
	}
	return "", ""
}

// ---------------------------------------------------------------------------
// R / CRAN — DESCRIPTION
// ---------------------------------------------------------------------------

func parseDescriptionScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// Imports, Depends, Suggests fields list packages (possibly with version reqs).
	var pkgs []ScopedPackage
	content := string(data)

	// Extract multi-line field value.
	extractField := func(field string) string {
		prefix := field + ":"
		idx := strings.Index(content, prefix)
		if idx < 0 {
			return ""
		}
		rest := content[idx+len(prefix):]
		// Value continues while lines start with whitespace.
		var sb strings.Builder
		for i, line := range strings.Split(rest, "\n") {
			if i == 0 {
				sb.WriteString(line)
				continue
			}
			if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
				sb.WriteString(line)
			} else {
				break
			}
		}
		return sb.String()
	}

	parseField := func(raw, scope string) {
		for _, entry := range strings.Split(raw, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			// Strip version constraint: "pkg (>= 1.0)" → "pkg"
			name := entry
			if idx := strings.Index(name, "("); idx > 0 {
				name = strings.TrimSpace(name[:idx])
			}
			if name == "" || name == "R" {
				continue
			}
			pkgs = append(pkgs, ScopedPackage{Name: name, Ecosystem: "cran", Scope: scope, IsDirect: true})
		}
	}

	parseField(extractField("Imports"), ScopeProduction)
	parseField(extractField("Depends"), ScopeProduction)
	parseField(extractField("Suggests"), ScopeDevelopment)
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// R / CRAN — renv.lock (JSON)
// ---------------------------------------------------------------------------

func parseRenvLockScoped(data []byte, _ string) ([]ScopedPackage, error) {
	var lock struct {
		Packages map[string]struct {
			Package string `json:"Package"`
			Version string `json:"Version"`
		} `json:"Packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, nil //nolint:nilerr
	}
	var pkgs []ScopedPackage
	for _, pkg := range lock.Packages {
		pkgs = append(pkgs, ScopedPackage{
			Name: pkg.Package, Version: pkg.Version,
			Ecosystem: "cran", Scope: ScopeProduction,
		})
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Erlang / rebar3 — rebar.config
// ---------------------------------------------------------------------------

func parseRebarConfigScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// {deps, [{pkg_name, "1.2.3"}, {pkg2, "~> 1.0"}, …]}.
	depRe := regexp.MustCompile(`\{([a-z_][a-zA-Z0-9_@]*)\s*,\s*"([^"]*)"`)
	var pkgs []ScopedPackage
	inDeps := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "%") {
			continue
		}
		if strings.Contains(line, "{deps") {
			inDeps = true
		}
		if !inDeps {
			continue
		}
		for _, m := range depRe.FindAllStringSubmatch(line, -1) {
			pkgs = append(pkgs, ScopedPackage{
				Name: m[1], Version: cleanLocalVersion(m[2]),
				Ecosystem: "hex", Scope: ScopeProduction, IsDirect: true,
			})
		}
		if strings.Contains(line, "}.") || strings.HasSuffix(strings.TrimSpace(line), "}.") {
			inDeps = false
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Erlang / rebar3 — rebar.lock
// ---------------------------------------------------------------------------

func parseRebarLockScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// {<<"pkg_name">>,{pkg,<<"pkg_name">>,<<"1.2.3">>},0}.
	nameRe := regexp.MustCompile(`<<"([^"]+)">>,\{pkg,<<"[^"]+">>,<<"([^"]+)">>`)
	var pkgs []ScopedPackage
	for _, line := range strings.Split(string(data), "\n") {
		m := nameRe.FindStringSubmatch(line)
		if m != nil {
			pkgs = append(pkgs, ScopedPackage{
				Name: m[1], Version: m[2],
				Ecosystem: "hex", Scope: ScopeProduction,
			})
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Haskell / Stack — stack.yaml
// ---------------------------------------------------------------------------

func parseStackYAMLScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// extra-deps:
	//   - acme-1.2.3
	//   - acme-1.2.3@sha256:…
	//   - github: owner/repo
	var pkgs []ScopedPackage
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	inExtraDeps := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "extra-deps:") {
			inExtraDeps = true
			continue
		}
		if inExtraDeps && len(line) > 0 && line[0] != ' ' && line[0] != '\t' && line[0] != '-' {
			inExtraDeps = false
			continue
		}
		if !inExtraDeps {
			continue
		}
		entry := strings.TrimPrefix(trimmed, "- ")
		// Strip sha256 hash.
		if idx := strings.Index(entry, "@sha256:"); idx > 0 {
			entry = entry[:idx]
		}
		// "name-version" format (last dash separates name from version).
		if idx := strings.LastIndex(entry, "-"); idx > 0 {
			name := entry[:idx]
			ver := entry[idx+1:]
			pkgs = append(pkgs, ScopedPackage{Name: name, Version: ver, Ecosystem: "hackage", Scope: ScopeProduction})
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Haskell / Cabal — *.cabal
// ---------------------------------------------------------------------------

func parseCabalScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// build-depends: base >=4.14, bytestring ^>=0.11, …
	var pkgs []ScopedPackage
	content := string(data)
	bdRe := regexp.MustCompile(`(?i)build-depends\s*:([\s\S]+?)(?:\n[a-z]|\z)`)
	for _, m := range bdRe.FindAllStringSubmatch(content, -1) {
		for _, part := range strings.Split(m[1], ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			fields := strings.Fields(part)
			if len(fields) == 0 {
				continue
			}
			name := fields[0]
			ver := ""
			if len(fields) >= 3 {
				ver = strings.Join(fields[1:], "")
			}
			pkgs = append(pkgs, ScopedPackage{Name: name, Version: ver, Ecosystem: "hackage", Scope: ScopeProduction, IsDirect: true})
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Haskell / Cabal — cabal.project.freeze
// ---------------------------------------------------------------------------

func parseCabalFreezeScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// constraints: pkg ==1.2.3, pkg2 ==0.1 …
	var pkgs []ScopedPackage
	content := string(data)
	// Strip continuation backslashes and join into single logical lines.
	content = strings.ReplaceAll(content, "\\\n", " ")
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "--") || line == "" {
			continue
		}
		if strings.HasPrefix(line, "constraints:") {
			line = strings.TrimPrefix(line, "constraints:")
		}
		for _, part := range strings.Split(line, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			fields := strings.Fields(part)
			if len(fields) == 0 {
				continue
			}
			name := fields[0]
			ver := ""
			if len(fields) >= 3 && fields[1] == "==" {
				ver = fields[2]
			} else if len(fields) >= 2 {
				ver = strings.TrimPrefix(fields[1], "==")
			}
			pkgs = append(pkgs, ScopedPackage{Name: name, Version: ver, Ecosystem: "hackage", Scope: ScopeProduction})
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// OCaml / opam — *.opam
// ---------------------------------------------------------------------------

func parseOpamScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// depends: [ "pkg" {>= "1.0"} "other" "conf-zlib" ]
	var pkgs []ScopedPackage
	content := string(data)
	depRe := regexp.MustCompile(`"([a-zA-Z0-9_-]+)"(?:\s*\{[^}]*\})?`)
	depsIdx := strings.Index(content, "depends:")
	if depsIdx < 0 {
		return nil, nil
	}
	rest := content[depsIdx+len("depends:"):]
	// Find the bracketed list.
	start := strings.Index(rest, "[")
	end := strings.Index(rest, "]")
	if start < 0 || end <= start {
		return nil, nil
	}
	block := rest[start+1 : end]
	for _, m := range depRe.FindAllStringSubmatch(block, -1) {
		name := m[1]
		if strings.HasPrefix(name, "conf-") || name == "ocaml" || name == "dune" {
			// Skip non-library deps.
			continue
		}
		pkgs = append(pkgs, ScopedPackage{Name: name, Ecosystem: "opam", Scope: ScopeProduction, IsDirect: true})
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Nix — flake.nix (extract inputs)
// ---------------------------------------------------------------------------

func parseFlakeNixScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// inputs.pkgname.url = "github:owner/repo/rev";
	// or:  pkgname = { url = "…"; … };
	urlRe := regexp.MustCompile(`url\s*=\s*"([^"]+)"`)
	var pkgs []ScopedPackage
	for _, line := range strings.Split(string(data), "\n") {
		m := urlRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		url := m[1]
		name, ver := parseFlakeURL(url)
		if name != "" {
			pkgs = append(pkgs, ScopedPackage{Name: name, Version: ver, Ecosystem: "nix", Scope: ScopeProduction, IsDirect: true})
		}
	}
	return pkgs, nil
}

func parseFlakeURL(url string) (name, ver string) {
	// "github:NixOS/nixpkgs/23.11" → name="nixpkgs" ver="23.11"
	url = strings.TrimPrefix(url, "github:")
	url = strings.TrimPrefix(url, "gitlab:")
	url = strings.TrimPrefix(url, "sourcehut:")
	parts := strings.Split(url, "/")
	switch len(parts) {
	case 1:
		return parts[0], ""
	case 2:
		return parts[1], ""
	default:
		return parts[1], parts[2]
	}
}

// ---------------------------------------------------------------------------
// Nix — flake.lock (JSON)
// ---------------------------------------------------------------------------

func parseFlakeLockScoped(data []byte, _ string) ([]ScopedPackage, error) {
	var lock struct {
		Nodes map[string]struct {
			Locked struct {
				Type string `json:"type"`
				Rev  string `json:"rev"`
				Tag  string `json:"tag"`
				Ref  string `json:"ref"`
			} `json:"locked"`
		} `json:"nodes"`
		Root struct {
			Inputs map[string]json.RawMessage `json:"inputs"`
		} `json:"root"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, nil //nolint:nilerr
	}
	var pkgs []ScopedPackage
	for name, node := range lock.Nodes {
		if name == "root" {
			continue
		}
		ver := node.Locked.Tag
		if ver == "" {
			ver = node.Locked.Ref
		}
		if ver == "" && len(node.Locked.Rev) >= 8 {
			ver = node.Locked.Rev[:8]
		}
		pkgs = append(pkgs, ScopedPackage{Name: name, Version: ver, Ecosystem: "nix", Scope: ScopeProduction})
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Zig — build.zig.zon
// ---------------------------------------------------------------------------

func parseZigZonScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// .dependencies = .{
	//     .pkg_name = .{
	//         .url = "…",
	//         .hash = "…",
	//     },
	// }
	var pkgs []ScopedPackage
	lines := strings.Split(string(data), "\n")
	inDeps := false
	var currentName string
	var currentURL string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, ".dependencies") && strings.Contains(trimmed, "=") {
			inDeps = true
			continue
		}
		if !inDeps {
			continue
		}
		// Entry name:  .pkg_name = .{
		if strings.HasPrefix(trimmed, ".") && strings.Contains(trimmed, "= .{") {
			currentName = strings.TrimPrefix(strings.Fields(trimmed)[0], ".")
			currentURL = ""
			continue
		}
		if strings.HasPrefix(trimmed, ".url = ") {
			currentURL = strings.Trim(strings.TrimPrefix(trimmed, ".url = "), `",`)
		}
		if trimmed == "}," && currentName != "" {
			name, ver := parseZigURL(currentURL)
			if name == "" {
				name = currentName
			}
			pkgs = append(pkgs, ScopedPackage{Name: name, Version: ver, Ecosystem: "zig", Scope: ScopeProduction, IsDirect: true})
			currentName, currentURL = "", ""
		}
	}
	return pkgs, nil
}

func parseZigURL(url string) (name, ver string) {
	if idx := strings.LastIndex(url, "/"); idx >= 0 {
		name = url[idx+1:]
		// Strip common suffixes.
		name = strings.TrimSuffix(name, ".tar.gz")
		name = strings.TrimSuffix(name, ".zip")
	}
	return name, ""
}

// ---------------------------------------------------------------------------
// CMake / CPM — CPM.cmake
// ---------------------------------------------------------------------------

func parseCPMCmakeScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// CPMAddPackage("gh:owner/repo@version")
	// CPMAddPackage(NAME foo VERSION 1.2 …)
	var pkgs []ScopedPackage
	ghRe := regexp.MustCompile(`CPMAddPackage\s*\(\s*"gh:([^@"]+)@([^"]+)"`)
	nameRe := regexp.MustCompile(`CPMAddPackage\s*\(`)
	namePropRe := regexp.MustCompile(`(?i)NAME\s+(\S+)`)
	verPropRe := regexp.MustCompile(`(?i)VERSION\s+(\S+)`)

	content := string(data)
	for _, m := range ghRe.FindAllStringSubmatch(content, -1) {
		repo := m[1]
		if idx := strings.LastIndex(repo, "/"); idx >= 0 {
			repo = repo[idx+1:]
		}
		pkgs = append(pkgs, ScopedPackage{Name: repo, Version: m[2], Ecosystem: "cpm", Scope: ScopeProduction, IsDirect: true})
	}

	// Multi-line CPMAddPackage(NAME … VERSION …)
	blocks := nameRe.Split(content, -1)
	for _, block := range blocks[1:] {
		nameM := namePropRe.FindStringSubmatch(block)
		verM := verPropRe.FindStringSubmatch(block)
		if nameM == nil {
			continue
		}
		ver := ""
		if verM != nil {
			ver = verM[1]
		}
		pkgs = append(pkgs, ScopedPackage{Name: nameM[1], Version: ver, Ecosystem: "cpm", Scope: ScopeProduction, IsDirect: true})
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Meson — meson.build
// ---------------------------------------------------------------------------

func parseMesonBuildScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// dependency('libfoo', version: '>=1.2')
	// subproject('foo', …)
	depRe := regexp.MustCompile(`(?:dependency|subproject)\s*\(\s*'([^']+)'`)
	verRe := regexp.MustCompile(`version\s*:\s*'([^']+)'`)
	var pkgs []ScopedPackage
	content := string(data)
	for _, line := range strings.Split(content, "\n") {
		m := depRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ver := ""
		if mv := verRe.FindStringSubmatch(line); mv != nil {
			ver = cleanLocalVersion(mv[1])
		}
		pkgs = append(pkgs, ScopedPackage{Name: m[1], Version: ver, Ecosystem: "meson", Scope: ScopeProduction, IsDirect: true})
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Bazel — WORKSPACE / WORKSPACE.bazel
// ---------------------------------------------------------------------------

func parseWorkspaceScoped(data []byte, _ string) ([]ScopedPackage, error) {
	// maven_install( artifacts = [ "group:artifact:version", … ] )
	// go_repository( name = "…", importpath = "…", version = "…" )
	var pkgs []ScopedPackage
	content := string(data)

	// Maven artifacts.
	mvnRe := regexp.MustCompile(`"([a-zA-Z0-9_.\-]+:[a-zA-Z0-9_.\-]+:[0-9][^"]*)"`)
	for _, m := range mvnRe.FindAllStringSubmatch(content, -1) {
		parts := strings.Split(m[1], ":")
		if len(parts) >= 3 {
			pkgs = append(pkgs, ScopedPackage{Name: parts[0] + ":" + parts[1], Version: parts[2], Ecosystem: "maven", Scope: ScopeProduction, IsDirect: true})
		}
	}

	// Go repositories.
	goRepoRe := regexp.MustCompile(`go_repository\s*\(([^)]+)\)`)
	importRe := regexp.MustCompile(`importpath\s*=\s*"([^"]+)"`)
	verGoRe := regexp.MustCompile(`version\s*=\s*"([^"]+)"`)
	for _, m := range goRepoRe.FindAllStringSubmatch(content, -1) {
		block := m[1]
		impM := importRe.FindStringSubmatch(block)
		if impM == nil {
			continue
		}
		ver := ""
		if mv := verGoRe.FindStringSubmatch(block); mv != nil {
			ver = mv[1]
		}
		pkgs = append(pkgs, ScopedPackage{Name: impM[1], Version: ver, Ecosystem: "golang", Scope: ScopeProduction, IsDirect: true})
	}
	return pkgs, nil
}
