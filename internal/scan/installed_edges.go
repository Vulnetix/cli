package scan

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// PopulateInstalledEdges attempts to build dependency graph edges for each
// manifest group by reading locally installed package manifests. This enriches
// both SBOM dependency trees and --paths output. Errors are silently skipped.
func PopulateInstalledEdges(groups []ManifestGroup, rootPath string) {
	for i := range groups {
		mg := &groups[i]
		if mg.Graph == nil {
			continue
		}
		projectDir := filepath.Join(rootPath, mg.Dir)
		switch mg.Ecosystem {
		case "npm":
			populateNpmInstalledEdges(mg.Graph, projectDir)
		case "pypi":
			populatePypiInstalledEdges(mg.Graph, projectDir)
		case "cargo":
			populateCargoInstalledEdges(mg.Graph, projectDir, mg.Dir)
		case "rubygems":
			populateRubyInstalledEdges(mg.Graph, projectDir)
		case "composer":
			populateComposerInstalledEdges(mg.Graph, projectDir)
		case "golang":
			if err := mg.Graph.PopulateGoModGraph(projectDir); err != nil {
				fmt.Fprintf(os.Stderr, "  warning: go mod graph failed in %s: %v\n", mg.Dir, err)
			}
		}
	}
}

// ── npm ─────────────────────────────────────────────────────────────────────

// populateNpmInstalledEdges walks node_modules/ to build dependency edges
// from each package's own package.json "dependencies" field.
// Falls back to PopulateNpmLockEdges if node_modules/ does not exist.
func populateNpmInstalledEdges(g *DepGraph, projectDir string) {
	nodeModDir := filepath.Join(projectDir, "node_modules")
	if info, err := os.Stat(nodeModDir); err != nil || !info.IsDir() {
		// Fallback: try package-lock.json edge parsing with absolute path.
		lockPath := filepath.Join(projectDir, "package-lock.json")
		_ = g.PopulateNpmLockEdges(lockPath)
		return
	}

	if g.Edges == nil {
		g.Edges = make(map[string][]string)
	}

	entries, err := os.ReadDir(nodeModDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue // skip .bin, .cache, .pnpm, etc.
		}
		if strings.HasPrefix(name, "@") {
			// Scoped package: read sub-entries.
			scopedDir := filepath.Join(nodeModDir, name)
			scopedEntries, err := os.ReadDir(scopedDir)
			if err != nil {
				continue
			}
			for _, se := range scopedEntries {
				readNpmPkgDeps(g, nodeModDir, name+"/"+se.Name())
			}
		} else {
			readNpmPkgDeps(g, nodeModDir, name)
		}
	}

	// Also walk pnpm virtual store for transitive deps not hoisted to top level.
	pnpmDir := filepath.Join(nodeModDir, ".pnpm")
	if info, err := os.Stat(pnpmDir); err == nil && info.IsDir() {
		populatePnpmVirtualStore(g, pnpmDir)
	}
}

// readNpmPkgDeps reads a single package.json and adds its dependencies as edges.
func readNpmPkgDeps(g *DepGraph, nodeModDir, pkgName string) {
	pkgJSONPath := filepath.Join(nodeModDir, pkgName, "package.json")
	data, err := os.ReadFile(pkgJSONPath)
	if err != nil {
		return
	}
	var pj struct {
		Dependencies map[string]string `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &pj); err != nil {
		return
	}
	if len(pj.Dependencies) > 0 {
		deps := make([]string, 0, len(pj.Dependencies))
		for dep := range pj.Dependencies {
			deps = append(deps, dep)
		}
		g.Edges[pkgName] = deps
	}
}

// populatePnpmVirtualStore walks .pnpm/<pkg@ver>/node_modules/ to pick up
// transitive dependencies that are not hoisted to the top-level node_modules/.
func populatePnpmVirtualStore(g *DepGraph, pnpmDir string) {
	entries, err := os.ReadDir(pnpmDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		nmDir := filepath.Join(pnpmDir, entry.Name(), "node_modules")
		pkgEntries, err := os.ReadDir(nmDir)
		if err != nil {
			continue
		}
		for _, pe := range pkgEntries {
			name := pe.Name()
			if strings.HasPrefix(name, ".") {
				continue
			}
			if strings.HasPrefix(name, "@") {
				scopedEntries, err := os.ReadDir(filepath.Join(nmDir, name))
				if err != nil {
					continue
				}
				for _, se := range scopedEntries {
					pkgName := name + "/" + se.Name()
					if _, exists := g.Edges[pkgName]; !exists {
						readNpmPkgDeps(g, nmDir, pkgName)
					}
				}
			} else {
				if _, exists := g.Edges[name]; !exists {
					readNpmPkgDeps(g, nmDir, name)
				}
			}
		}
	}
}

// ── Python ──────────────────────────────────────────────────────────────────

// populatePypiInstalledEdges detects the active Python venv, walks
// site-packages/*.dist-info/METADATA, and extracts Requires-Dist edges.
func populatePypiInstalledEdges(g *DepGraph, projectDir string) {
	venvRoot := findPythonVenv(projectDir)
	if venvRoot == "" {
		return
	}
	sitePackages := findSitePackages(venvRoot)
	if sitePackages == "" {
		return
	}

	if g.Edges == nil {
		g.Edges = make(map[string][]string)
	}

	entries, err := os.ReadDir(sitePackages)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasSuffix(entry.Name(), ".dist-info") {
			continue
		}
		metadataPath := filepath.Join(sitePackages, entry.Name(), "METADATA")
		name, deps := parsePythonMetadata(metadataPath)
		if name != "" {
			g.Edges[name] = deps
		}
	}
}

// findPythonVenv locates the active Python virtual environment root.
// Priority: VIRTUAL_ENV > CONDA_PREFIX > directory walk > UV_PROJECT_ENVIRONMENT.
func findPythonVenv(projectDir string) string {
	if v := os.Getenv("VIRTUAL_ENV"); v != "" {
		if _, err := os.Stat(filepath.Join(v, "pyvenv.cfg")); err == nil {
			return v
		}
	}
	if v := os.Getenv("CONDA_PREFIX"); v != "" {
		return v
	}
	// Walk up from projectDir (max 5 levels) looking for common venv dirs.
	dir := projectDir
	for range 5 {
		for _, name := range []string{".venv", "venv", ".env", "env"} {
			candidate := filepath.Join(dir, name)
			if _, err := os.Stat(filepath.Join(candidate, "pyvenv.cfg")); err == nil {
				return candidate
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	if v := os.Getenv("UV_PROJECT_ENVIRONMENT"); v != "" {
		return v
	}
	return ""
}

// findSitePackages returns the site-packages directory inside a venv root.
func findSitePackages(venvRoot string) string {
	if runtime.GOOS == "windows" {
		sp := filepath.Join(venvRoot, "Lib", "site-packages")
		if _, err := os.Stat(sp); err == nil {
			return sp
		}
		return ""
	}
	matches, _ := filepath.Glob(filepath.Join(venvRoot, "lib", "python3.*", "site-packages"))
	if len(matches) > 0 {
		return matches[0]
	}
	matches, _ = filepath.Glob(filepath.Join(venvRoot, "lib", "python*", "site-packages"))
	if len(matches) > 0 {
		return matches[0]
	}
	return ""
}

// normPypi normalises a Python package name for consistent edge keys.
func normPypi(n string) string {
	return strings.ToLower(strings.NewReplacer("-", "_", ".", "_").Replace(n))
}

// parsePythonMetadata parses a METADATA file (RFC 822 headers) and returns
// the normalised package name and its dependency names.
func parsePythonMetadata(path string) (name string, deps []string) {
	f, err := os.Open(path)
	if err != nil {
		return "", nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break // end of headers
		}
		if v, ok := strings.CutPrefix(line, "Name: "); ok {
			name = normPypi(v)
		} else if dep, ok := strings.CutPrefix(line, "Requires-Dist: "); ok {
			// Skip optional extras (markers containing "extra ==").
			if strings.Contains(dep, "; ") {
				marker := dep[strings.Index(dep, "; ")+2:]
				if strings.Contains(marker, "extra ==") || strings.Contains(marker, "extra==") {
					continue
				}
			}
			// Extract package name (before version specifier or markers).
			depName := dep
			for i, c := range dep {
				if c == ' ' || c == '(' || c == ';' || c == '[' || c == '<' || c == '>' || c == '=' || c == '!' || c == '~' {
					depName = dep[:i]
					break
				}
			}
			depName = strings.TrimSpace(depName)
			if depName != "" {
				deps = append(deps, normPypi(depName))
			}
		}
	}
	return name, deps
}

// ── Rust ────────────────────────────────────────────────────────────────────

// populateCargoInstalledEdges runs "cargo metadata" and builds edges from the
// resolve graph. Prints a warning to stderr on failure (like Go).
func populateCargoInstalledEdges(g *DepGraph, projectDir, relDir string) {
	cmd := exec.Command("cargo", "metadata", "--format-version", "1")
	cmd.Dir = projectDir
	out, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  warning: cargo metadata failed in %s: %v\n", relDir, err)
		return
	}

	var metadata struct {
		Resolve struct {
			Nodes []struct {
				ID   string `json:"id"`
				Deps []struct {
					Name string `json:"name"`
				} `json:"deps"`
			} `json:"nodes"`
		} `json:"resolve"`
	}
	if err := json.Unmarshal(out, &metadata); err != nil {
		return
	}

	if g.Edges == nil {
		g.Edges = make(map[string][]string)
	}

	for _, node := range metadata.Resolve.Nodes {
		// ID format: "name version (source+...)" — extract name.
		parts := strings.SplitN(node.ID, " ", 2)
		nodeName := parts[0]
		var deps []string
		for _, d := range node.Deps {
			deps = append(deps, d.Name)
		}
		if len(deps) > 0 {
			g.Edges[nodeName] = deps
		}
	}
}

// ── Ruby ────────────────────────────────────────────────────────────────────

var gemDepRegex = regexp.MustCompile(`add_(?:runtime_)?dependency\s+['"]([^'"]+)['"]`)

// populateRubyInstalledEdges parses gemspec files from installed gems to build edges.
func populateRubyInstalledEdges(g *DepGraph, projectDir string) {
	gemsDir := findRubyGemsDir(projectDir)
	if gemsDir == "" {
		return
	}

	if g.Edges == nil {
		g.Edges = make(map[string][]string)
	}

	entries, err := os.ReadDir(gemsDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		gemspecDir := filepath.Join(gemsDir, entry.Name())
		gemspecs, _ := filepath.Glob(filepath.Join(gemspecDir, "*.gemspec"))
		if len(gemspecs) == 0 {
			continue
		}
		gemName := extractGemName(entry.Name())
		deps := parseGemspecDeps(gemspecs[0])
		if len(deps) > 0 {
			g.Edges[gemName] = deps
		}
	}
}

// findRubyGemsDir locates the installed gems directory.
// Priority: vendor/bundle > GEM_HOME > GEM_PATH first entry.
func findRubyGemsDir(projectDir string) string {
	matches, _ := filepath.Glob(filepath.Join(projectDir, "vendor", "bundle", "ruby", "*", "gems"))
	if len(matches) > 0 {
		return matches[0]
	}
	if v := os.Getenv("GEM_HOME"); v != "" {
		gemsDir := filepath.Join(v, "gems")
		if _, err := os.Stat(gemsDir); err == nil {
			return gemsDir
		}
	}
	if v := os.Getenv("GEM_PATH"); v != "" {
		first := strings.SplitN(v, string(os.PathListSeparator), 2)[0]
		gemsDir := filepath.Join(first, "gems")
		if _, err := os.Stat(gemsDir); err == nil {
			return gemsDir
		}
	}
	return ""
}

// extractGemName strips the trailing -<version> from a gem directory name.
func extractGemName(dirName string) string {
	for i := len(dirName) - 1; i >= 0; i-- {
		if dirName[i] == '-' && i+1 < len(dirName) && dirName[i+1] >= '0' && dirName[i+1] <= '9' {
			return dirName[:i]
		}
	}
	return dirName
}

// parseGemspecDeps scans a .gemspec file for add_dependency / add_runtime_dependency calls.
func parseGemspecDeps(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var deps []string
	for _, match := range gemDepRegex.FindAllSubmatch(data, -1) {
		if len(match) > 1 {
			deps = append(deps, string(match[1]))
		}
	}
	return deps
}

// ── PHP / Composer ──────────────────────────────────────────────────────────

// populateComposerInstalledEdges walks vendor/<org>/<pkg>/composer.json and
// extracts the "require" field (skipping platform requirements).
func populateComposerInstalledEdges(g *DepGraph, projectDir string) {
	vendorDir := filepath.Join(projectDir, "vendor")
	if info, err := os.Stat(vendorDir); err != nil || !info.IsDir() {
		return
	}

	if g.Edges == nil {
		g.Edges = make(map[string][]string)
	}

	orgs, err := os.ReadDir(vendorDir)
	if err != nil {
		return
	}
	for _, org := range orgs {
		if !org.IsDir() || strings.HasPrefix(org.Name(), ".") {
			continue
		}
		orgDir := filepath.Join(vendorDir, org.Name())
		pkgs, err := os.ReadDir(orgDir)
		if err != nil {
			continue
		}
		for _, pkg := range pkgs {
			if !pkg.IsDir() {
				continue
			}
			composerPath := filepath.Join(orgDir, pkg.Name(), "composer.json")
			deps := parseComposerDeps(composerPath)
			pkgName := org.Name() + "/" + pkg.Name()
			if len(deps) > 0 {
				g.Edges[pkgName] = deps
			}
		}
	}
}

// parseComposerDeps reads a composer.json and returns non-platform require keys.
func parseComposerDeps(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var cj struct {
		Require map[string]string `json:"require"`
	}
	if err := json.Unmarshal(data, &cj); err != nil {
		return nil
	}
	var deps []string
	for name := range cj.Require {
		if name == "php" || strings.HasPrefix(name, "ext-") || strings.HasPrefix(name, "lib-") {
			continue
		}
		deps = append(deps, name)
	}
	return deps
}
