package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var npmLockfileNames = []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}

type npmInstalledPackage struct {
	Name         string
	Version      string
	PackageDir   string
	Dependencies map[string]string
}

// NpmLockfilePresent reports whether a package.json has a sibling npm-family
// lockfile. The no-lock installed resolver only runs when this returns false.
func NpmLockfilePresent(packageJSONPath string) bool {
	dir := filepath.Dir(packageJSONPath)
	for _, name := range npmLockfileNames {
		if info, err := os.Stat(filepath.Join(dir, name)); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}

// npmBuildOrLockHint is the remediation shown when an npm package.json has no
// lockfile and its declared dependencies cannot be fully resolved from
// node_modules. Either remediation restores a scannable state: building the app
// (npm/yarn/pnpm install) populates node_modules and writes a lockfile, or
// generating a lockfile alone pins exact versions for the scanner. Without one
// of these, a package.json only carries version ranges, which cannot be scanned
// for vulnerabilities at exact versions.
func npmBuildOrLockHint(relPath string) string {
	return fmt.Sprintf("%s has no lockfile: build the app (run npm/yarn/pnpm install) or generate a lock file (package-lock.json, yarn.lock, or pnpm-lock.yaml), then re-run the scan", relPath)
}

// ResolveNpmPackageJSONFromNodeModules replaces package.json version ranges with
// installed versions when no lockfile exists, and adds installed transitives by
// reading every package manifest found under node_modules.
func ResolveNpmPackageJSONFromNodeModules(packageJSONPath, relPath string, direct []ScopedPackage) ([]ScopedPackage, error) {
	projectDir := filepath.Dir(packageJSONPath)
	nodeModDir := filepath.Join(projectDir, "node_modules")
	if info, err := os.Stat(nodeModDir); err != nil || !info.IsDir() {
		return nil, errors.New(npmBuildOrLockHint(relPath))
	}

	installed, err := readNpmInstalledPackages(nodeModDir)
	if err != nil {
		return nil, fmt.Errorf("%s (could not read node_modules: %w)", npmBuildOrLockHint(relPath), err)
	}

	directByName := make(map[string]ScopedPackage, len(direct))
	var missing []string
	for _, p := range direct {
		if p.Name == "" {
			continue
		}
		directByName[p.Name] = p
		if _, ok := installed[p.Name]; ok {
			continue
		}
		// optionalDependencies are allowed by npm to be absent (e.g.
		// platform-specific binaries that fail to install), so a missing one is
		// not evidence of an incomplete install. Every other declared dependency
		// must be present, or the node_modules tree cannot be trusted as a
		// complete substitute for a lockfile.
		if p.Scope == ScopeOptional {
			continue
		}
		missing = append(missing, p.Name)
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("%s — node_modules is missing declared dependencies: %s", npmBuildOrLockHint(relPath), strings.Join(missing, ", "))
	}

	names := make([]string, 0, len(installed))
	for name := range installed {
		names = append(names, name)
	}
	sort.Strings(names)

	manifestDir := filepath.Dir(relPath)
	out := make([]ScopedPackage, 0, len(names))
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		pkg := installed[name]
		sp := ScopedPackage{
			Name:       pkg.Name,
			Version:    pkg.Version,
			Ecosystem:  "npm",
			SourceFile: relPath,
			IsDirect:   false,
			// Found by walking node_modules, not declared — flag it so remediation
			// knows it can't be fixed by editing the manifest. Overridden to
			// "manifest" below when the package is also a declared dependency.
			SourceType:    SourceTypeInstalled,
			InstalledPath: installedRelPath(manifestDir, projectDir, pkg.PackageDir),
		}
		if d, ok := directByName[name]; ok {
			sp.Scope = d.Scope
			sp.VersionSpec = d.VersionSpec
			sp.IsDirect = true
			// Declared in the manifest — that's the actionable source; the install
			// location is irrelevant for remediation, so drop it.
			sp.SourceType = SourceTypeManifest
			sp.InstalledPath = ""
		}
		key := sp.Name + "@" + sp.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, sp)
	}
	return out, nil
}

// installedRelPath renders a node_modules package directory as a path relative to
// the scan root: the manifest's directory (already root-relative) joined with the
// package dir's path relative to the project. Returns "" when unresolvable.
func installedRelPath(manifestDir, projectDir, packageDir string) string {
	if packageDir == "" {
		return ""
	}
	rel, err := filepath.Rel(projectDir, packageDir)
	if err != nil {
		return ""
	}
	if manifestDir == "" || manifestDir == "." {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(filepath.Join(manifestDir, rel))
}

func readNpmInstalledPackages(nodeModDir string) (map[string]npmInstalledPackage, error) {
	pkgs := map[string]npmInstalledPackage{}
	if err := walkNpmNodeModules(nodeModDir, pkgs, map[string]bool{}); err != nil {
		return nil, err
	}
	return pkgs, nil
}

func walkNpmNodeModules(nodeModDir string, pkgs map[string]npmInstalledPackage, visited map[string]bool) error {
	realDir, err := filepath.EvalSymlinks(nodeModDir)
	if err != nil {
		realDir = nodeModDir
	}
	if visited[realDir] {
		return nil
	}
	visited[realDir] = true

	entries, err := os.ReadDir(nodeModDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		entryPath := filepath.Join(nodeModDir, name)
		if !npmDirEntryIsDir(entryPath, entry) {
			continue
		}
		if strings.HasPrefix(name, "@") {
			scopedEntries, err := os.ReadDir(entryPath)
			if err != nil {
				continue
			}
			for _, scoped := range scopedEntries {
				scopedName := scoped.Name()
				scopedPath := filepath.Join(entryPath, scopedName)
				if !npmDirEntryIsDir(scopedPath, scoped) {
					continue
				}
				readNpmInstalledPackage(scopedPath, name+"/"+scopedName, pkgs, visited)
			}
			continue
		}
		readNpmInstalledPackage(entryPath, name, pkgs, visited)
	}
	return nil
}

func npmDirEntryIsDir(path string, entry os.DirEntry) bool {
	if entry.IsDir() {
		return true
	}
	if entry.Type()&os.ModeSymlink == 0 {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func readNpmInstalledPackage(pkgDir, fallbackName string, pkgs map[string]npmInstalledPackage, visited map[string]bool) {
	pkg, ok := parseNpmInstalledPackageJSON(filepath.Join(pkgDir, "package.json"), fallbackName)
	if !ok {
		return
	}
	pkg.PackageDir = pkgDir
	if _, exists := pkgs[pkg.Name]; !exists {
		pkgs[pkg.Name] = pkg
	}

	nestedNodeModules := filepath.Join(pkgDir, "node_modules")
	if info, err := os.Stat(nestedNodeModules); err == nil && info.IsDir() {
		_ = walkNpmNodeModules(nestedNodeModules, pkgs, visited)
	}
}

func parseNpmInstalledPackageJSON(path, fallbackName string) (npmInstalledPackage, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return npmInstalledPackage{}, false
	}
	var pj struct {
		Name                 string            `json:"name"`
		Version              string            `json:"version"`
		Dependencies         map[string]string `json:"dependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(data, &pj); err != nil {
		return npmInstalledPackage{}, false
	}
	name := strings.TrimSpace(pj.Name)
	if name == "" {
		name = fallbackName
	}
	if name == "" || strings.TrimSpace(pj.Version) == "" {
		return npmInstalledPackage{}, false
	}
	deps := make(map[string]string, len(pj.Dependencies)+len(pj.PeerDependencies)+len(pj.OptionalDependencies))
	for dep, r := range pj.Dependencies {
		deps[dep] = r
	}
	for dep, r := range pj.OptionalDependencies {
		if _, ok := deps[dep]; !ok {
			deps[dep] = r
		}
	}
	for dep, r := range pj.PeerDependencies {
		if _, ok := deps[dep]; !ok {
			deps[dep] = r
		}
	}
	return npmInstalledPackage{Name: name, Version: strings.TrimSpace(pj.Version), Dependencies: deps}, true
}

func populateNpmGraphFromInstalled(g *DepGraph, installed map[string]npmInstalledPackage) {
	if g == nil {
		return
	}
	if g.Edges == nil {
		g.Edges = make(map[string][]string)
	}
	if g.EdgeRanges == nil {
		g.EdgeRanges = make(map[string]map[string]string)
	}
	for name, pkg := range installed {
		if len(pkg.Dependencies) == 0 {
			continue
		}
		children := make([]string, 0, len(pkg.Dependencies))
		for dep, r := range pkg.Dependencies {
			if _, ok := installed[dep]; !ok {
				continue
			}
			children = append(children, dep)
			if r != "" {
				if g.EdgeRanges[name] == nil {
					g.EdgeRanges[name] = make(map[string]string)
				}
				g.EdgeRanges[name][dep] = r
			}
		}
		if len(children) == 0 {
			continue
		}
		sort.Strings(children)
		g.Edges[name] = dedupeStrings(append(g.Edges[name], children...))
	}
}

func dedupeStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	sort.Strings(values)
	out := values[:0]
	for _, v := range values {
		if len(out) == 0 || out[len(out)-1] != v {
			out = append(out, v)
		}
	}
	return out
}
