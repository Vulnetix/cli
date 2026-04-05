package scan

import (
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
func (g *DepGraph) IsDirect(pkgName string) bool {
	if g == nil {
		return true // no graph data — assume direct
	}
	_, ok := g.DirectDeps[pkgName]
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
		}

		result = append(result, mg)
	}
	return result
}
