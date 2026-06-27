package scan

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// DepGraph tracks direct vs transitive dependency relationships for a manifest group.
// A manifest group is a set of related files in the same directory (e.g., go.mod + go.sum).
type DepGraph struct {
	DirectDeps map[string]ScopedPackage     // name → direct dependency
	AllDeps    map[string]ScopedPackage     // name → any dependency (direct or transitive)
	Edges      map[string][]string          // parent module name → child module names (from go mod graph, etc.)
	EdgeRanges map[string]map[string]string // parent → child → declared range, when the lock/manifest exposes it

	pathCache map[string][]string // memoised FindPath results, see FindPathMemo
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

// FindPathMemo is a memoised FindPath. The shortest chain to a given package is
// identical no matter which vulnerability references it, yet the display path was
// previously recomputed per finding (and again by the pretty-printer), making the
// introduced-paths render O(vulns × manifests × BFS). Callers share one *DepGraph,
// so caching on the graph collapses that to one BFS per distinct package.
//
// Not safe for concurrent use; FindPath is only ever called from the sequential
// enrichment and rendering loops, consistent with the rest of DepGraph.
func (g *DepGraph) FindPathMemo(target string) []string {
	if g == nil {
		return nil
	}
	if cached, ok := g.pathCache[target]; ok {
		return cached
	}
	chain := g.FindPath(target)
	if g.pathCache == nil {
		g.pathCache = map[string][]string{}
	}
	g.pathCache[target] = chain
	return chain
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
	if g.EdgeRanges == nil {
		g.EdgeRanges = make(map[string]map[string]string)
	}

	type npmLockPkg struct {
		Dependencies     map[string]string `json:"dependencies"`
		PeerDependencies map[string]string `json:"peerDependencies"`
	}
	var lockWithDeps struct {
		Packages map[string]npmLockPkg `json:"packages"`
	}
	if err := json.Unmarshal(data, &lockWithDeps); err != nil {
		return err
	}

	pathToName := func(path string) string {
		if path == "" {
			return ""
		}
		cleaned := path
		if strings.HasPrefix(cleaned, "node_modules/") {
			cleaned = strings.TrimPrefix(cleaned, "node_modules/")
		}
		if idx := strings.LastIndex(cleaned, "/node_modules/"); idx >= 0 {
			return cleaned[idx+len("/node_modules/"):]
		}
		return cleaned
	}
	addEdge := func(parent, child, declaredRange string) {
		if parent == "" || child == "" {
			return
		}
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
		if declaredRange != "" {
			if g.EdgeRanges[parent] == nil {
				g.EdgeRanges[parent] = make(map[string]string)
			}
			g.EdgeRanges[parent][child] = declaredRange
		}
	}

	// Prefer declared dependency maps: they expose the exact parent-child range
	// strings package-lock v2/v3 recorded for each installed package.
	for path, pkg := range lockWithDeps.Packages {
		parent := pathToName(path)
		if parent == "" {
			continue
		}
		for child, r := range pkg.Dependencies {
			addEdge(parent, child, r)
		}
		for child, r := range pkg.PeerDependencies {
			addEdge(parent, child, r)
		}
	}

	// Fallback: build edges from the nested node_modules path structure.
	// "node_modules/express/node_modules/body-parser" → express depends on body-parser.
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
			addEdge(parent, child, "")
		}
		// Top-level packages (no nested node_modules) are direct deps — no edge needed
		// since they're already in DirectDeps.
	}

	return nil
}

// PopulatePypiLockEdges builds dependency-tree edges for a pypi manifest group
// from the lock files in dir. Edge keys/values are normalised (normPypi) so the
// lock, `# via`, and installed-METADATA sources all merge on one key form;
// BuildDependencies resolves SBOM component names against the same normalisation.
// uv.lock and pylock.toml carry an explicit dependency tree; a `pip/uv compile`
// requirements.txt carries it as inverted `# via` comments. All present sources
// are merged.
func (g *DepGraph) PopulatePypiLockEdges(dir string) {
	if g == nil {
		return
	}
	if g.Edges == nil {
		g.Edges = make(map[string][]string)
	}

	// uv.lock — richest tree (explicit dependencies + optional-dependencies).
	if data, err := os.ReadFile(filepath.Join(dir, "uv.lock")); err == nil {
		var lock uvLockFile
		if _, derr := toml.Decode(string(data), &lock); derr == nil {
			for _, p := range lock.Package {
				var children []string
				for _, d := range p.Dependencies {
					if d.Name != "" {
						children = append(children, d.Name)
					}
				}
				for _, deps := range p.OptionalDependencies {
					for _, d := range deps {
						if d.Name != "" {
							children = append(children, d.Name)
						}
					}
				}
				g.addEdges(normPypi(p.Name), normPypiList(children))
			}
		}
	}

	// pylock.toml — PEP 751 per-package dependencies, when the generator emits them.
	if data, err := os.ReadFile(filepath.Join(dir, "pylock.toml")); err == nil {
		var lock pylockFile
		if _, derr := toml.Decode(string(data), &lock); derr == nil {
			for _, p := range lock.Packages {
				var children []string
				for _, d := range p.Dependencies {
					if d.Name != "" {
						children = append(children, d.Name)
					}
				}
				g.addEdges(normPypi(p.Name), normPypiList(children))
			}
		}
	}

	// requirements.txt — invert the `# via` comments (only tree source when no
	// lock file exists alongside a compiled, hashed requirements.txt).
	if data, err := os.ReadFile(filepath.Join(dir, "requirements.txt")); err == nil {
		for parent, children := range parseRequirementsViaEdges(string(data)) {
			g.addEdges(normPypi(parent), normPypiList(children))
		}
	}
}

// normPypiList normalises a list of PyPI package names (dropping empties).
func normPypiList(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n != "" {
			out = append(out, normPypi(n))
		}
	}
	return out
}

// addEdges appends children under parent, de-duplicating existing edges.
func (g *DepGraph) addEdges(parent string, children []string) {
	if parent == "" || len(children) == 0 {
		return
	}
	existing := make(map[string]bool, len(g.Edges[parent]))
	for _, c := range g.Edges[parent] {
		existing[c] = true
	}
	for _, c := range children {
		if c != "" && !existing[c] {
			g.Edges[parent] = append(g.Edges[parent], c)
			existing[c] = true
		}
	}
}

// parseRequirementsViaEdges inverts the `# via` annotations of a compiled
// requirements.txt into forward edges (parent → child). A `# via -r file`
// reference is an include, not a parent package, and is skipped.
func parseRequirementsViaEdges(content string) map[string][]string {
	edges := map[string][]string{}
	curName := ""
	curVia := false
	for _, ll := range joinReqContinuations(content) {
		line := strings.TrimSpace(ll)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if curName == "" {
				continue
			}
			body := strings.TrimSpace(strings.TrimPrefix(line, "#"))
			if rest, ok := strings.CutPrefix(body, "via"); ok {
				curVia = true
				body = strings.TrimSpace(rest)
			}
			if !curVia || body == "" || isRequirementsInclude(body) {
				continue
			}
			if parent, _, _, ok := parsePEP508(body); ok && parent != "" {
				edges[parent] = append(edges[parent], curName)
			}
			continue
		}
		curVia = false
		if strings.HasPrefix(line, "-") {
			curName = ""
			continue
		}
		if ci := strings.Index(line, " #"); ci >= 0 {
			line = strings.TrimSpace(line[:ci])
		}
		var specParts []string
		for _, tok := range strings.Fields(line) {
			if strings.HasPrefix(tok, "--hash=") {
				continue
			}
			specParts = append(specParts, tok)
		}
		if name, _, _, ok := parsePEP508(strings.Join(specParts, " ")); ok {
			curName = name
		} else {
			curName = ""
		}
	}
	return edges
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
		if p.IsDirect {
			g.DirectDeps[p.Name] = p
		}
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
				case "pyproject.toml", "requirements.in":
					directPkgs = append(directPkgs, pkgs...)
				case "uv.lock", "pipfile.lock", "poetry.lock", "pylock.toml", "requirements.txt":
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
