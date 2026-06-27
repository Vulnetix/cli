package scan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func init() {
	gateRegistry["nuget"] = gateSpec{
		gated:       func(t string) bool { return t == "*.csproj" || t == "paket.dependencies" },
		lockPresent: func(dir string) bool { return anySiblingExists(dir, []string{"packages.lock.json", "paket.lock"}) },
		fullyPinned: allVersionsPinned, // PackageReference versions are usually exact
		resolve:     ResolveNugetFromInstalled,
	}
}

// nugetKey: NuGet package ids are case-insensitive.
func nugetKey(n string) string { return strings.ToLower(n) }

func nugetBuildOrLockHint(relPath string) string {
	return fmt.Sprintf("%s has no packages.lock.json and its packages are not restored: build the app (dotnet restore) or enable a lock file (RestorePackagesWithLockFile), then re-run the scan", relPath)
}

// ResolveNugetFromInstalled resolves project deps from a local `packages/` folder
// (old packages.config layout, full) or the global NuGet cache (declared-only).
func ResolveNugetFromInstalled(manifestPath, relPath string, declared []ScopedPackage, strict bool) ([]ScopedPackage, error) {
	projectDir := filepath.Dir(manifestPath)
	manifestDir := filepath.Dir(relPath)

	if installed := readNugetPackagesDir(filepath.Join(projectDir, "packages")); len(installed) > 0 {
		return resolveFromProjectInstall(relPath, manifestDir, projectDir, "nuget", declared, installed, nugetKey, strict, nugetBuildOrLockHint)
	}

	globalRoot := os.Getenv("NUGET_PACKAGES")
	if globalRoot == "" {
		if h := homeDir(); h != "" {
			globalRoot = filepath.Join(h, ".nuget", "packages")
		}
	}
	if globalRoot != "" {
		if installed := lookupNugetGlobal(globalRoot, declared); len(installed) > 0 {
			return resolveFromGlobalInstall(relPath, "nuget", declared, installed, nugetKey, strict, nugetBuildOrLockHint)
		}
	}
	return nil, errors.New(nugetBuildOrLockHint(relPath))
}

// readNugetPackagesDir reads the legacy packages.config layout
// "packages/<Id>.<Version>/" (version starts at the first dotted numeric segment).
func readNugetPackagesDir(dir string) map[string]installedDep {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := map[string]installedDep{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name, ver := splitNugetDirName(e.Name())
		if name == "" || ver == "" {
			continue
		}
		k := nugetKey(name)
		if _, ok := out[k]; !ok {
			out[k] = installedDep{Name: name, Version: ver, Dir: filepath.Join(dir, e.Name())}
		}
	}
	return out
}

// splitNugetDirName splits "Newtonsoft.Json.13.0.3" into id and version at the
// first dot-segment that is purely numeric.
func splitNugetDirName(stem string) (name, version string) {
	parts := strings.Split(stem, ".")
	for i := 1; i < len(parts); i++ {
		if _, ok := atoiSafe(parts[i]); ok && parts[i] != "" && parts[i][0] >= '0' && parts[i][0] <= '9' {
			return strings.Join(parts[:i], "."), strings.Join(parts[i:], ".")
		}
	}
	return stem, ""
}

// lookupNugetGlobal resolves each declared id under ~/.nuget/packages/<id-lower>/<ver>/.
func lookupNugetGlobal(globalRoot string, declared []ScopedPackage) map[string]installedDep {
	out := map[string]installedDep{}
	for _, p := range declared {
		if p.Name == "" {
			continue
		}
		base := filepath.Join(globalRoot, nugetKey(p.Name))
		ver, dir, ok := resolveNestedVersion(base, p.Version)
		if !ok {
			continue
		}
		out[nugetKey(p.Name)] = installedDep{Name: p.Name, Version: ver, Dir: dir}
	}
	return out
}
