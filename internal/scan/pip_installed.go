package scan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// pyLockSiblingNames are Python lock files that, when present next to a manifest,
// mean a fully-pinned set will be scanned — so the manifest itself needs no
// build-or-lock gate.
var pyLockSiblingNames = []string{"uv.lock", "poetry.lock", "Pipfile.lock", "pylock.toml"}

// PyGatedManifestTypes are the Python manifest types the build-or-lock gate
// applies to: unpinned manifests that need a lock or an installed env to scan at
// exact versions. Lock files are never gated.
func IsPythonGatedManifest(manifestType string) bool {
	switch manifestType {
	case "requirements.txt", "requirements.in", "pyproject.toml", "Pipfile":
		return true
	}
	return false
}

// PyLockfilePresent reports whether dir contains any Python lock file. When one
// exists the lock is scanned with exact versions, so an unpinned sibling manifest
// does not need resolving from the installed environment.
func PyLockfilePresent(dir string) bool {
	for _, name := range pyLockSiblingNames {
		if info, err := os.Stat(filepath.Join(dir, name)); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}

// RequirementsFullyLocked reports whether every package is pinned enough to scan
// without consulting the installed environment: an exact version pin OR integrity
// hashes (pip freeze / pip-compile / pylock output). A bare name (no version, no
// hash) is not locked — its empty VersionSpec must not be mistaken for a pin.
func RequirementsFullyLocked(pkgs []ScopedPackage) bool {
	if len(pkgs) == 0 {
		return false
	}
	for _, p := range pkgs {
		if len(p.Checksums) > 0 {
			continue
		}
		if p.Version != "" && IsVersionSpecPinned(p.VersionSpec) {
			continue
		}
		return false
	}
	return true
}

// pipBuildOrLockHint is the remediation shown when a pip manifest is neither
// version-locked nor installed. Either remediation restores a scannable state:
// building the app populates site-packages, or a lock file pins exact versions.
func pipBuildOrLockHint(relPath string) string {
	return fmt.Sprintf("%s has no lock file and its dependencies are not installed: build the app (pip install / uv sync) or generate a lock file (pip freeze, pip-compile, uv lock, or pylock.toml), then re-run the scan", relPath)
}

// installedPy is an installed Python distribution discovered in site-packages.
type installedPy struct {
	Name    string // distribution name from the dist-info/egg-info dir (pre-normalisation)
	Version string
	Dir     string // absolute dist-info/egg-info directory
}

// readInstalledPythonPackages maps normPypi(name) → installed distribution by
// reading the `*.dist-info` / `*.egg-info` directory names in site-packages (the
// version is encoded in the directory name; no METADATA read required).
func readInstalledPythonPackages(sitePackages string) (map[string]installedPy, error) {
	entries, err := os.ReadDir(sitePackages)
	if err != nil {
		return nil, err
	}
	out := make(map[string]installedPy)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		var stem string
		switch {
		case strings.HasSuffix(name, ".dist-info"):
			stem = strings.TrimSuffix(name, ".dist-info")
		case strings.HasSuffix(name, ".egg-info"):
			stem = strings.TrimSuffix(name, ".egg-info")
		default:
			continue
		}
		distName, version := splitDistInfoStem(stem)
		if distName == "" {
			continue
		}
		key := normPypi(distName)
		if _, exists := out[key]; !exists {
			out[key] = installedPy{Name: distName, Version: version, Dir: filepath.Join(sitePackages, name)}
		}
	}
	return out, nil
}

// splitDistInfoStem splits a dist-info/egg-info stem ("attrs-25.3.0",
// "jsonschema_specifications-2025.4.1", "foo-1.0-py3.11") into name and version,
// taking the first dash-separated segment that begins with a digit as the version.
func splitDistInfoStem(stem string) (name, version string) {
	parts := strings.Split(stem, "-")
	for i := 1; i < len(parts); i++ {
		if parts[i] != "" && parts[i][0] >= '0' && parts[i][0] <= '9' {
			return strings.Join(parts[:i], "-"), parts[i]
		}
	}
	return stem, ""
}

// ResolvePythonRequirementsFromSitePackages resolves an unpinned pip manifest's
// declared packages to exact installed versions. It mirrors the npm node_modules
// resolver, including SourceType/InstalledPath provenance.
//
// A project venv (findPythonVenv) yields a full project-scoped resolution:
// declared packages (SourceType=manifest) plus every installed package as a
// transitive (SourceType=installed, InstalledPath set). When no venv is found it
// falls back to the global/user site-packages purely as an install check,
// resolving the declared packages only (globals are never enumerated into the
// SBOM as project dependencies).
//
// strict (a confident detection) requires every declared package to be present,
// else it errors with the build-or-lock hint. Non-strict (a tentative detection)
// keeps whatever resolves and errors only when nothing matches.
func ResolvePythonRequirementsFromSitePackages(manifestPath, relPath string, declared []ScopedPackage, strict bool) ([]ScopedPackage, error) {
	projectDir := filepath.Dir(manifestPath)
	manifestDir := filepath.Dir(relPath)

	if venv := findPythonVenv(projectDir); venv != "" {
		if sp := findSitePackages(venv); sp != "" {
			if installed, err := readInstalledPythonPackages(sp); err == nil && len(installed) > 0 {
				return resolvePythonFromVenv(relPath, manifestDir, projectDir, declared, installed, strict)
			}
		}
	}
	return resolvePythonFromGlobal(relPath, declared, strict)
}

// resolvePythonFromVenv builds the resolved set from a project venv: all installed
// packages as transitives, with declared packages overlaid as direct manifest deps.
func resolvePythonFromVenv(relPath, manifestDir, projectDir string, declared []ScopedPackage, installed map[string]installedPy, strict bool) ([]ScopedPackage, error) {
	declaredByNorm := make(map[string]ScopedPackage, len(declared))
	var missing []string
	matched := 0
	for _, p := range declared {
		if p.Name == "" {
			continue
		}
		nk := normPypi(p.Name)
		declaredByNorm[nk] = p
		if _, ok := installed[nk]; ok {
			matched++
		} else {
			missing = append(missing, p.Name)
		}
	}
	if strict && len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("%s — not installed in the environment: %s", pipBuildOrLockHint(relPath), strings.Join(missing, ", "))
	}
	if !strict && matched == 0 {
		// Tentative file: none of its names are installed → not a confirmed
		// requirements file.
		return nil, errors.New(pipBuildOrLockHint(relPath))
	}

	keys := make([]string, 0, len(installed))
	for k := range installed {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]ScopedPackage, 0, len(keys))
	seen := make(map[string]bool, len(keys))
	for _, nk := range keys {
		inst := installed[nk]
		sp := ScopedPackage{
			Name:          inst.Name,
			Version:       inst.Version,
			Ecosystem:     "pypi",
			Scope:         ScopeProduction,
			SourceFile:    relPath,
			IsDirect:      false,
			SourceType:    SourceTypeInstalled,
			InstalledPath: installedRelPath(manifestDir, projectDir, inst.Dir),
		}
		if d, ok := declaredByNorm[nk]; ok {
			sp.Name = d.Name // preserve the manifest's spelling/casing
			sp.Scope = orProduction(d.Scope)
			sp.VersionSpec = d.VersionSpec
			sp.IsDirect = true
			sp.SourceType = SourceTypeManifest
			sp.InstalledPath = ""
		}
		key := normPypi(sp.Name) + "@" + sp.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, sp)
	}
	return out, nil
}

// resolvePythonFromGlobal resolves declared packages against the global/user
// site-packages as an install check only. It does not enumerate the global
// environment as project transitives.
func resolvePythonFromGlobal(relPath string, declared []ScopedPackage, strict bool) ([]ScopedPackage, error) {
	installed := make(map[string]installedPy)
	for _, dir := range globalSitePackages() {
		m, err := readInstalledPythonPackages(dir)
		if err != nil {
			continue
		}
		for k, v := range m {
			if _, ok := installed[k]; !ok {
				installed[k] = v
			}
		}
	}

	var out []ScopedPackage
	var missing []string
	for _, p := range declared {
		if p.Name == "" {
			continue
		}
		inst, ok := installed[normPypi(p.Name)]
		if !ok {
			missing = append(missing, p.Name)
			continue
		}
		out = append(out, ScopedPackage{
			Name:        p.Name,
			Version:     inst.Version,
			VersionSpec: p.VersionSpec,
			Ecosystem:   "pypi",
			Scope:       orProduction(p.Scope),
			SourceFile:  relPath,
			IsDirect:    true,
			// Declared in the manifest; the global install location is not a
			// project path, so it is not surfaced as an InstalledPath.
			SourceType: SourceTypeManifest,
		})
	}
	if len(out) == 0 {
		return nil, errors.New(pipBuildOrLockHint(relPath))
	}
	if strict && len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("%s — not installed in the environment: %s", pipBuildOrLockHint(relPath), strings.Join(missing, ", "))
	}
	return out, nil
}

// globalSitePackages returns best-effort global/user site-packages directories,
// used only as an install-check fallback when no project venv exists.
func globalSitePackages() []string {
	var dirs []string
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if m, _ := filepath.Glob(filepath.Join(home, ".local", "lib", "python*", "site-packages")); len(m) > 0 {
			dirs = append(dirs, m...)
		}
		if runtime.GOOS == "darwin" {
			if m, _ := filepath.Glob(filepath.Join(home, "Library", "Python", "*", "lib", "python", "site-packages")); len(m) > 0 {
				dirs = append(dirs, m...)
			}
		}
	}
	switch runtime.GOOS {
	case "windows":
		// %APPDATA%\Python\Python3X\site-packages and the interpreter's Lib.
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			if m, _ := filepath.Glob(filepath.Join(appdata, "Python", "Python*", "site-packages")); len(m) > 0 {
				dirs = append(dirs, m...)
			}
		}
	default:
		for _, root := range []string{"/usr/lib", "/usr/local/lib", "/usr/lib64"} {
			for _, leaf := range []string{"site-packages", "dist-packages"} {
				if m, _ := filepath.Glob(filepath.Join(root, "python3*", leaf)); len(m) > 0 {
					dirs = append(dirs, m...)
				}
			}
		}
	}
	return dirs
}

// orProduction returns scope, defaulting to production when empty.
func orProduction(scope string) string {
	if scope == "" {
		return ScopeProduction
	}
	return scope
}
