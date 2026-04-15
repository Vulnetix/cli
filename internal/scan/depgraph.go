package scan

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DepGraph tracks direct vs transitive dependency relationships for a manifest group.
// A manifest group is a set of related files in the same directory (e.g., go.mod + go.sum).
type DepGraph struct {
	DirectDeps map[string]ScopedPackage // name → direct dependency
	AllDeps    map[string]ScopedPackage // name → any dependency (direct or transitive)
	Edges      map[string][]string      // parent module name → child module names (from go mod graph, etc.)
}

// IsDirect returns true if the package was declared directly in the manifest.
// For PyPI packages, name lookup is also attempted with dash/underscore/case
// normalisation so that e.g. "PyYAML" matches a key stored as "pyyaml".
func (g *DepGraph) IsDirect(pkgName string) bool {
	if g == nil {
		return true // no graph data — assume direct
	}
	if _, ok := g.DirectDeps[pkgName]; ok {
		return ok
	}
	// Normalised fallback for PyPI (dashes, underscores, case).
	norm := strings.ToLower(strings.NewReplacer("-", "_", ".", "_").Replace(pkgName))
	_, ok := g.DirectDeps[norm]
	return ok
}

// DirectCount returns the number of direct dependencies.
func (g *DepGraph) DirectCount() int {
	if g == nil {
		return 0
	}
	return len(g.DirectDeps)
}

// TransitiveCount returns the number of transitive (non-direct) dependencies.
func (g *DepGraph) TransitiveCount() int {
	if g == nil {
		return 0
	}
	count := 0
	for name := range g.AllDeps {
		if _, isDirect := g.DirectDeps[name]; !isDirect {
			count++
		}
	}
	return count
}

// FindPath returns the shortest dependency chain from any direct dep to targetPkg.
// Returns nil if no path exists or edge data is unavailable.
// The returned slice is the chain: [direct-dep, intermediate, ..., targetPkg].
func (g *DepGraph) FindPath(targetPkg string) []string {
	if g == nil || len(g.Edges) == 0 {
		return nil
	}

	// BFS from each direct dep to targetPkg.
	type queueEntry struct {
		node string
		path []string
	}

	// Build reverse lookup: strip version from package names in edges.
	// Edge keys may include versions from "go mod graph" (e.g., "golang.org/x/net@v0.47.0").
	// We match on module name prefix only.
	visited := map[string]bool{}
	queue := []queueEntry{}

	// Seed with direct deps.
	for name := range g.DirectDeps {
		queue = append(queue, queueEntry{node: name, path: []string{name}})
		visited[name] = true
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		if cur.node == targetPkg {
			return cur.path
		}

		for _, child := range g.Edges[cur.node] {
			if !visited[child] {
				visited[child] = true
				newPath := make([]string, len(cur.path)+1)
				copy(newPath, cur.path)
				newPath[len(cur.path)] = child
				if child == targetPkg {
					return newPath
				}
				queue = append(queue, queueEntry{node: child, path: newPath})
			}
		}
	}
	return nil
}

// PopulateGoModGraph runs "go mod graph" in the given directory and populates
// the Edges map with the dependency relationships. Strips version suffixes
// so edges use bare module names matching package names.
func (g *DepGraph) PopulateGoModGraph(dir string) error {
	if g == nil {
		return nil
	}
	cmd := exec.Command("go", "mod", "graph")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return err
	}

	g.Edges = make(map[string][]string)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		parent := stripVersion(parts[0])
		child := stripVersion(parts[1])
		g.Edges[parent] = append(g.Edges[parent], child)
	}
	return nil
}

// stripVersion removes the @vX.Y.Z suffix from a Go module path.
func stripVersion(mod string) string {
	if idx := strings.LastIndex(mod, "@"); idx > 0 {
		return mod[:idx]
	}
	return mod
}

// PopulateNpmLockEdges parses package-lock.json (v2/v3) and populates the
// Edges map from the nested node_modules path structure.
// In v3 format, the key "node_modules/foo/node_modules/bar" means foo depends on bar.
func (g *DepGraph) PopulateNpmLockEdges(lockFilePath string) error {
	if g == nil {
		return nil
	}
	data, err := os.ReadFile(lockFilePath)
	if err != nil {
		return err
	}

	var lock struct {
		LockfileVersion int                    `json:"lockfileVersion"`
		Packages        map[string]interface{} `json:"packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return err
	}

	if g.Edges == nil {
		g.Edges = make(map[string][]string)
	}

	// Build edges from the nested node_modules path structure.
	// "node_modules/express/node_modules/body-parser" → express depends on body-parser
	// "node_modules/express" (no nesting) → root depends on express
	for path := range lock.Packages {
		if path == "" {
			continue // root package
		}
		// Strip leading "node_modules/"
		cleaned := path
		if strings.HasPrefix(cleaned, "node_modules/") {
			cleaned = strings.TrimPrefix(cleaned, "node_modules/")
		}

		// Find the last "node_modules/" separator to determine parent → child.
		if idx := strings.LastIndex(cleaned, "/node_modules/"); idx >= 0 {
			parent := cleaned[:idx]
			// Handle scoped packages in parent (e.g., @scope/pkg).
			child := cleaned[idx+len("/node_modules/"):]
			seen := false
			for _, existing := range g.Edges[parent] {
				if existing == child {
					seen = true
					break
				}
			}
			if !seen {
				g.Edges[parent] = append(g.Edges[parent], child)
			}
		}
		// Top-level packages (no nested node_modules) are direct deps — no edge needed
		// since they're already in DirectDeps.
	}

	return nil
}

// BuildGoDepGraph correlates go.mod (direct) and go.sum (all) packages from the
// same directory to determine which dependencies are direct vs transitive.
func BuildGoDepGraph(goModPkgs, goSumPkgs []ScopedPackage) *DepGraph {
	g := &DepGraph{
		DirectDeps: make(map[string]ScopedPackage),
		AllDeps:    make(map[string]ScopedPackage),
	}
	for _, p := range goModPkgs {
		g.DirectDeps[p.Name] = p
		g.AllDeps[p.Name] = p
	}
	for _, p := range goSumPkgs {
		if _, exists := g.AllDeps[p.Name]; !exists {
			g.AllDeps[p.Name] = p
		}
	}
	return g
}

// BuildPypiDepGraph correlates pyproject.toml (direct) and lock files (uv.lock,
// poetry.lock, Pipfile.lock) to classify direct vs transitive dependencies.
// Package name comparison is case-folded and normalises dashes/underscores
// to handle the common PyPI naming quirks.
func BuildPypiDepGraph(directPkgs, lockPkgs []ScopedPackage) *DepGraph {
	g := &DepGraph{
		DirectDeps: make(map[string]ScopedPackage),
		AllDeps:    make(map[string]ScopedPackage),
	}
	normPypi := func(n string) string {
		return strings.ToLower(strings.NewReplacer("-", "_", ".", "_").Replace(n))
	}
	for _, p := range directPkgs {
		k := normPypi(p.Name)
		g.DirectDeps[k] = p
		g.AllDeps[k] = p
	}
	for _, p := range lockPkgs {
		k := normPypi(p.Name)
		if _, exists := g.AllDeps[k]; !exists {
			g.AllDeps[k] = p
		}
	}
	return g
}

// IsDirect for pypi needs the same normalisation — covered by IsDirect above.

// BuildGenericDepGraph is a generic build graph correlator for ecosystems that have
// a simple direct manifest + lock file relationship (e.g., Cargo.toml/Cargo.lock).
func BuildGenericDepGraph(directPkgs, lockPkgs []ScopedPackage) *DepGraph {
	g := &DepGraph{
		DirectDeps: make(map[string]ScopedPackage),
		AllDeps:    make(map[string]ScopedPackage),
	}
	for _, p := range directPkgs {
		g.DirectDeps[p.Name] = p
		g.AllDeps[p.Name] = p
	}
	for _, p := range lockPkgs {
		if _, exists := g.AllDeps[p.Name]; !exists {
			g.AllDeps[p.Name] = p
		}
	}
	return g
}

// BuildNpmDepGraph correlates package.json (direct) and package-lock.json (all)
// packages from the same directory.
func BuildNpmDepGraph(pkgJsonPkgs, lockPkgs []ScopedPackage) *DepGraph {
	g := &DepGraph{
		DirectDeps: make(map[string]ScopedPackage),
		AllDeps:    make(map[string]ScopedPackage),
	}
	for _, p := range pkgJsonPkgs {
		g.DirectDeps[p.Name] = p
		g.AllDeps[p.Name] = p
	}
	for _, p := range lockPkgs {
		if _, exists := g.AllDeps[p.Name]; !exists {
			g.AllDeps[p.Name] = p
		}
	}
	return g
}

// manifestGroupKey returns the directory + ecosystem for grouping related manifest files.
func manifestGroupKey(relPath, ecosystem string) string {
	return filepath.Dir(relPath) + "::" + ecosystem
}

// ManifestGroup holds related manifest files from the same directory/ecosystem.
type ManifestGroup struct {
	Dir       string          // relative directory
	Ecosystem string          // e.g., "golang", "npm"
	Files     []string        // relative paths of constituent manifest files
	Graph     *DepGraph       // direct vs transitive classification
	Packages  []ScopedPackage // all packages from this group
}

// BuildManifestGroups correlates manifest results by directory and ecosystem,
// building dependency graphs where possible.
func BuildManifestGroups(filePackages map[string][]ScopedPackage, fileEcosystems map[string]string) []ManifestGroup {
	type groupData struct {
		dir       string
		ecosystem string
		files     map[string][]ScopedPackage
	}
	groups := map[string]*groupData{}

	for relPath, pkgs := range filePackages {
		eco := fileEcosystems[relPath]
		key := manifestGroupKey(relPath, eco)
		if _, ok := groups[key]; !ok {
			groups[key] = &groupData{
				dir:       filepath.Dir(relPath),
				ecosystem: eco,
				files:     make(map[string][]ScopedPackage),
			}
		}
		groups[key].files[relPath] = pkgs
	}

	var result []ManifestGroup
	for _, gd := range groups {
		mg := ManifestGroup{
			Dir:       gd.dir,
			Ecosystem: gd.ecosystem,
		}

		for relPath, pkgs := range gd.files {
			mg.Files = append(mg.Files, relPath)
			mg.Packages = append(mg.Packages, pkgs...)
		}

		switch gd.ecosystem {
		case "pypi":
			var directPkgs, lockPkgs []ScopedPackage
			for relPath, pkgs := range gd.files {
				base := strings.ToLower(filepath.Base(relPath))
				switch base {
				case "pyproject.toml":
					directPkgs = pkgs
				case "uv.lock", "pipfile.lock", "poetry.lock", "requirements.txt":
					lockPkgs = append(lockPkgs, pkgs...)
				}
			}
			if len(directPkgs) > 0 || len(lockPkgs) > 0 {
				mg.Graph = BuildPypiDepGraph(directPkgs, lockPkgs)
			}
		case "golang":
			var goModPkgs, goSumPkgs []ScopedPackage
			for relPath, pkgs := range gd.files {
				base := strings.ToLower(filepath.Base(relPath))
				switch base {
				case "go.mod":
					goModPkgs = pkgs
				case "go.sum":
					goSumPkgs = pkgs
				}
			}
			if len(goModPkgs) > 0 || len(goSumPkgs) > 0 {
				mg.Graph = BuildGoDepGraph(goModPkgs, goSumPkgs)
			}
		case "npm":
			var directPkgs, lockPkgs []ScopedPackage
			for relPath, pkgs := range gd.files {
				base := strings.ToLower(filepath.Base(relPath))
				switch base {
				case "package.json":
					directPkgs = pkgs
				case "package-lock.json", "yarn.lock", "pnpm-lock.yaml":
					lockPkgs = pkgs
				}
			}
			if len(directPkgs) > 0 || len(lockPkgs) > 0 {
				mg.Graph = BuildNpmDepGraph(directPkgs, lockPkgs)
			}
		case "rubygems":
			var directPkgs, lockPkgs []ScopedPackage
			for relPath, pkgs := range gd.files {
				base := filepath.Base(relPath)
				switch base {
				case "Gemfile":
					directPkgs = pkgs
				case "Gemfile.lock":
					lockPkgs = pkgs
				}
			}
			if len(directPkgs) > 0 || len(lockPkgs) > 0 {
				mg.Graph = BuildGenericDepGraph(directPkgs, lockPkgs)
			}
		case "cargo":
			var directPkgs, lockPkgs []ScopedPackage
			for relPath, pkgs := range gd.files {
				base := filepath.Base(relPath)
				switch base {
				case "Cargo.toml":
					directPkgs = pkgs
				case "Cargo.lock":
					lockPkgs = pkgs
				}
			}
			if len(directPkgs) > 0 || len(lockPkgs) > 0 {
				mg.Graph = BuildGenericDepGraph(directPkgs, lockPkgs)
			}
		case "composer":
			var directPkgs, lockPkgs []ScopedPackage
			for relPath, pkgs := range gd.files {
				base := filepath.Base(relPath)
				switch base {
				case "composer.json":
					directPkgs = pkgs
				case "composer.lock":
					lockPkgs = pkgs
				}
			}
			if len(directPkgs) > 0 || len(lockPkgs) > 0 {
				mg.Graph = BuildGenericDepGraph(directPkgs, lockPkgs)
			}
		case "maven":
			var directPkgs, lockPkgs []ScopedPackage
			for relPath, pkgs := range gd.files {
				base := filepath.Base(relPath)
				switch base {
				case "pom.xml", "build.gradle", "build.gradle.kts", "build.sbt":
					directPkgs = pkgs
				case "gradle.lockfile", "build.lock":
					lockPkgs = pkgs
				}
			}
			if len(directPkgs) > 0 || len(lockPkgs) > 0 {
				mg.Graph = BuildGenericDepGraph(directPkgs, lockPkgs)
			}
		case "nuget":
			var directPkgs, lockPkgs []ScopedPackage
			for relPath, pkgs := range gd.files {
				base := filepath.Base(relPath)
				switch base {
				case "paket.dependencies":
					directPkgs = pkgs
				case "packages.lock.json", "paket.lock":
					lockPkgs = append(lockPkgs, pkgs...)
				}
				// *.csproj also counts as direct
				if strings.HasSuffix(base, ".csproj") {
					directPkgs = append(directPkgs, pkgs...)
				}
			}
			if len(directPkgs) > 0 || len(lockPkgs) > 0 {
				mg.Graph = BuildGenericDepGraph(directPkgs, lockPkgs)
			}
		case "pub":
			var directPkgs, lockPkgs []ScopedPackage
			for relPath, pkgs := range gd.files {
				base := filepath.Base(relPath)
				switch base {
				case "pubspec.yaml":
					directPkgs = pkgs
				case "pubspec.lock":
					lockPkgs = pkgs
				}
			}
			if len(directPkgs) > 0 || len(lockPkgs) > 0 {
				mg.Graph = BuildGenericDepGraph(directPkgs, lockPkgs)
			}
		case "hex":
			var directPkgs, lockPkgs []ScopedPackage
			for relPath, pkgs := range gd.files {
				base := filepath.Base(relPath)
				switch base {
				case "mix.exs":
					directPkgs = pkgs
				case "mix.lock":
					lockPkgs = pkgs
				}
			}
			if len(directPkgs) > 0 || len(lockPkgs) > 0 {
				mg.Graph = BuildGenericDepGraph(directPkgs, lockPkgs)
			}
		case "swift":
			var directPkgs, lockPkgs []ScopedPackage
			for relPath, pkgs := range gd.files {
				base := filepath.Base(relPath)
				switch base {
				case "Package.swift":
					directPkgs = pkgs
				case "Package.resolved":
					lockPkgs = pkgs
				}
			}
			if len(directPkgs) > 0 || len(lockPkgs) > 0 {
				mg.Graph = BuildGenericDepGraph(directPkgs, lockPkgs)
			}
		case "cocoapods":
			var directPkgs, lockPkgs []ScopedPackage
			for relPath, pkgs := range gd.files {
				base := filepath.Base(relPath)
				switch base {
				case "Podfile":
					directPkgs = pkgs
				case "Podfile.lock":
					lockPkgs = pkgs
				}
			}
			if len(directPkgs) > 0 || len(lockPkgs) > 0 {
				mg.Graph = BuildGenericDepGraph(directPkgs, lockPkgs)
			}
		case "carthage":
			var directPkgs, lockPkgs []ScopedPackage
			for relPath, pkgs := range gd.files {
				base := filepath.Base(relPath)
				switch base {
				case "Cartfile":
					directPkgs = pkgs
				case "Cartfile.resolved":
					lockPkgs = pkgs
				}
			}
			if len(directPkgs) > 0 || len(lockPkgs) > 0 {
				mg.Graph = BuildGenericDepGraph(directPkgs, lockPkgs)
			}
		case "julia":
			var directPkgs, lockPkgs []ScopedPackage
			for relPath, pkgs := range gd.files {
				base := filepath.Base(relPath)
				switch base {
				case "Project.toml":
					directPkgs = pkgs
				case "Manifest.toml":
					lockPkgs = pkgs
				}
			}
			if len(directPkgs) > 0 || len(lockPkgs) > 0 {
				mg.Graph = BuildGenericDepGraph(directPkgs, lockPkgs)
			}
		case "crystal":
			var directPkgs, lockPkgs []ScopedPackage
			for relPath, pkgs := range gd.files {
				base := filepath.Base(relPath)
				switch base {
				case "shard.yml":
					directPkgs = pkgs
				case "shard.lock":
					lockPkgs = pkgs
				}
			}
			if len(directPkgs) > 0 || len(lockPkgs) > 0 {
				mg.Graph = BuildGenericDepGraph(directPkgs, lockPkgs)
			}
		case "deno":
			var directPkgs, lockPkgs []ScopedPackage
			for relPath, pkgs := range gd.files {
				base := filepath.Base(relPath)
				switch base {
				case "deno.json":
					directPkgs = pkgs
				case "deno.lock":
					lockPkgs = pkgs
				}
			}
			if len(directPkgs) > 0 || len(lockPkgs) > 0 {
				mg.Graph = BuildGenericDepGraph(directPkgs, lockPkgs)
			}
		case "cran":
			var directPkgs, lockPkgs []ScopedPackage
			for relPath, pkgs := range gd.files {
				base := filepath.Base(relPath)
				switch base {
				case "DESCRIPTION":
					directPkgs = pkgs
				case "renv.lock":
					lockPkgs = pkgs
				}
			}
			if len(directPkgs) > 0 || len(lockPkgs) > 0 {
				mg.Graph = BuildGenericDepGraph(directPkgs, lockPkgs)
			}
		case "erlang":
			var directPkgs, lockPkgs []ScopedPackage
			for relPath, pkgs := range gd.files {
				base := filepath.Base(relPath)
				switch base {
				case "rebar.config":
					directPkgs = pkgs
				case "rebar.lock":
					lockPkgs = pkgs
				}
			}
			if len(directPkgs) > 0 || len(lockPkgs) > 0 {
				mg.Graph = BuildGenericDepGraph(directPkgs, lockPkgs)
			}
		case "cabal":
			var directPkgs, lockPkgs []ScopedPackage
			for relPath, pkgs := range gd.files {
				base := filepath.Base(relPath)
				switch base {
				case "cabal.project.freeze":
					lockPkgs = pkgs
				}
				if strings.HasSuffix(base, ".cabal") {
					directPkgs = pkgs
				}
			}
			if len(directPkgs) > 0 || len(lockPkgs) > 0 {
				mg.Graph = BuildGenericDepGraph(directPkgs, lockPkgs)
			}
		case "conan":
			var directPkgs, lockPkgs []ScopedPackage
			for relPath, pkgs := range gd.files {
				base := filepath.Base(relPath)
				switch base {
				case "conanfile.txt":
					directPkgs = pkgs
				case "conan.lock":
					lockPkgs = pkgs
				}
			}
			if len(directPkgs) > 0 || len(lockPkgs) > 0 {
				mg.Graph = BuildGenericDepGraph(directPkgs, lockPkgs)
			}
		case "nix":
			var directPkgs, lockPkgs []ScopedPackage
			for relPath, pkgs := range gd.files {
				base := filepath.Base(relPath)
				switch base {
				case "flake.nix":
					directPkgs = pkgs
				case "flake.lock":
					lockPkgs = pkgs
				}
			}
			if len(directPkgs) > 0 || len(lockPkgs) > 0 {
				mg.Graph = BuildGenericDepGraph(directPkgs, lockPkgs)
			}
		}

		result = append(result, mg)
	}
	return result
}
