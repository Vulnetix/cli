package scan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// installedDep is an installed package discovered on disk.
type installedDep struct {
	Name    string // distribution name as discovered (preserves spelling for display)
	Version string
	Dir     string // absolute install dir (for InstalledPath); "" for global-cache hits
}

// splitNameVersion splits a "<name>-<version>" directory stem into name and
// version, taking the first dash-separated segment that begins with a digit as
// the version start (e.g. "activerecord-7.1.3.4" → "activerecord","7.1.3.4";
// "serde_json-1.0.0" → "serde_json","1.0.0").
func splitNameVersion(stem string) (name, version string) {
	parts := strings.Split(stem, "-")
	for i := 1; i < len(parts); i++ {
		if parts[i] != "" && parts[i][0] >= '0' && parts[i][0] <= '9' {
			return strings.Join(parts[:i], "-"), strings.Join(parts[i:], "-")
		}
	}
	return stem, ""
}

// readNameDashVersionDirs reads install directories laid out as "<name>-<version>"
// (cargo registry src, dart pub-cache, ruby gems) and returns a map keyed by
// keyFn(name). splitFn extracts (name, version) from a directory name; pass nil
// to use the generic splitNameVersion. The first occurrence of a key wins.
func readNameDashVersionDirs(dirs []string, splitFn func(string) (string, string), keyFn func(string) string) map[string]installedDep {
	if splitFn == nil {
		splitFn = splitNameVersion
	}
	out := map[string]installedDep{}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name, ver := splitFn(e.Name())
			if name == "" || ver == "" {
				continue
			}
			k := keyFn(name)
			if _, ok := out[k]; !ok {
				out[k] = installedDep{Name: name, Version: ver, Dir: filepath.Join(dir, e.Name())}
			}
		}
	}
	return out
}

// lowerName lower-cases a package name (case-insensitive ecosystems: nuget, pub).
func lowerName(n string) string { return strings.ToLower(n) }

// identName is the identity key function (case-sensitive ecosystems: rubygems, maven, go).
func identName(n string) string { return n }

// resolveFromProjectInstall builds a full project-scoped resolution: every
// installed package becomes a transitive (SourceType=installed, InstalledPath
// set), with declared packages overlaid as direct manifest deps. It mirrors
// resolvePythonFromVenv. strict=true requires every declared package present;
// strict=false (a tentative detection) keeps whatever resolves and errors only
// when nothing matches.
func resolveFromProjectInstall(relPath, manifestDir, projectDir, ecosystem string,
	declared []ScopedPackage, installed map[string]installedDep,
	keyFn func(string) string, strict bool, hint func(string) string) ([]ScopedPackage, error) {

	declaredByKey := make(map[string]ScopedPackage, len(declared))
	var missing []string
	matched := 0
	for _, p := range declared {
		if p.Name == "" {
			continue
		}
		k := keyFn(p.Name)
		declaredByKey[k] = p
		if _, ok := installed[k]; ok {
			matched++
		} else {
			missing = append(missing, p.Name)
		}
	}
	if strict && len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("%s — not installed: %s", hint(relPath), strings.Join(missing, ", "))
	}
	if !strict && matched == 0 {
		return nil, errors.New(hint(relPath))
	}

	keys := make([]string, 0, len(installed))
	for k := range installed {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]ScopedPackage, 0, len(keys))
	seen := make(map[string]bool, len(keys))
	for _, k := range keys {
		inst := installed[k]
		sp := ScopedPackage{
			Name:          inst.Name,
			Version:       inst.Version,
			Ecosystem:     ecosystem,
			Scope:         ScopeProduction,
			SourceFile:    relPath,
			IsDirect:      false,
			SourceType:    SourceTypeInstalled,
			InstalledPath: installedRelPath(manifestDir, projectDir, inst.Dir),
		}
		if d, ok := declaredByKey[k]; ok {
			sp.Name = d.Name
			sp.Scope = orProduction(d.Scope)
			sp.VersionSpec = d.VersionSpec
			sp.IsDirect = true
			sp.SourceType = SourceTypeManifest
			sp.InstalledPath = ""
		}
		dk := keyFn(sp.Name) + "@" + sp.Version
		if seen[dk] {
			continue
		}
		seen[dk] = true
		out = append(out, sp)
	}
	return out, nil
}

// resolveFromGlobalInstall resolves only the declared packages against a global
// cache (no transitive enumeration — a global cache holds every project's deps).
// Declared packages keep manifest provenance with no InstalledPath. It mirrors
// resolvePythonFromGlobal.
func resolveFromGlobalInstall(relPath, ecosystem string, declared []ScopedPackage,
	installed map[string]installedDep, keyFn func(string) string,
	strict bool, hint func(string) string) ([]ScopedPackage, error) {

	var out []ScopedPackage
	var missing []string
	for _, p := range declared {
		if p.Name == "" {
			continue
		}
		inst, ok := installed[keyFn(p.Name)]
		if !ok {
			missing = append(missing, p.Name)
			continue
		}
		out = append(out, ScopedPackage{
			Name:        p.Name,
			Version:     inst.Version,
			VersionSpec: p.VersionSpec,
			Ecosystem:   ecosystem,
			Scope:       orProduction(p.Scope),
			SourceFile:  relPath,
			IsDirect:    true,
			SourceType:  SourceTypeManifest,
		})
	}
	if len(out) == 0 {
		return nil, errors.New(hint(relPath))
	}
	if strict && len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("%s — not installed: %s", hint(relPath), strings.Join(missing, ", "))
	}
	return out, nil
}

// resolveNestedVersion inspects baseDir's version subdirectories (the
// "<id>/<version>/" layout of ~/.nuget and ~/.m2) and returns the declared
// version when it is installed, otherwise the highest installed version.
func resolveNestedVersion(baseDir, declaredVersion string) (version, dir string, ok bool) {
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return "", "", false
	}
	var versions []string
	for _, e := range entries {
		if e.IsDir() {
			versions = append(versions, e.Name())
		}
	}
	if len(versions) == 0 {
		return "", "", false
	}
	if declaredVersion != "" {
		for _, v := range versions {
			if v == declaredVersion {
				return v, filepath.Join(baseDir, v), true
			}
		}
	}
	best := versions[0]
	for _, v := range versions[1:] {
		if compareVersionStrings(v, best) > 0 {
			best = v
		}
	}
	return best, filepath.Join(baseDir, best), true
}

// compareVersionStrings does a best-effort dotted version comparison (numeric
// segments compared numerically, others lexically). Returns -1, 0, or 1.
func compareVersionStrings(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y string
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		xn, xerr := atoiSafe(x)
		yn, yerr := atoiSafe(y)
		if xerr && yerr {
			if xn != yn {
				if xn < yn {
					return -1
				}
				return 1
			}
			continue
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// atoiSafe parses a leading integer from s (stopping at the first non-digit, e.g.
// "1rc2" → 1). ok is false when s has no leading digit.
func atoiSafe(s string) (n int, ok bool) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		n = n*10 + int(s[i]-'0')
		i++
	}
	return n, i > 0
}

// homeDir returns the user's home directory, or "" if unavailable.
func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}

// firstExistingDir returns the first directory in candidates that exists, or "".
func firstExistingDir(candidates ...string) string {
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}
	return ""
}
