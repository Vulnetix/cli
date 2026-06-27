package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func init() {
	gateRegistry["composer"] = gateSpec{
		gated:       func(t string) bool { return t == "composer.json" },
		lockPresent: func(dir string) bool { return anySiblingExists(dir, []string{"composer.lock"}) },
		fullyPinned: nil, // composer.json specs are ranges (`^`, `~`, `>=`)
		resolve:     ResolveComposerFromInstalled,
	}
}

// composerKey: Composer package names ("vendor/name") are lower-case.
func composerKey(n string) string { return strings.ToLower(n) }

func composerBuildOrLockHint(relPath string) string {
	return fmt.Sprintf("%s has no composer.lock and its dependencies are not installed: build the app (composer install) or generate a lock file (composer update --lock), then re-run the scan", relPath)
}

// ResolveComposerFromInstalled resolves composer.json deps from the project
// `vendor/` tree (full transitive set). Composer has no versioned global cache, so
// a missing `vendor/` is a build-or-lock error.
func ResolveComposerFromInstalled(manifestPath, relPath string, declared []ScopedPackage, strict bool) ([]ScopedPackage, error) {
	projectDir := filepath.Dir(manifestPath)
	manifestDir := filepath.Dir(relPath)

	installed := readComposerVendor(filepath.Join(projectDir, "vendor"))
	if len(installed) == 0 {
		return nil, errors.New(composerBuildOrLockHint(relPath))
	}
	return resolveFromProjectInstall(relPath, manifestDir, projectDir, "composer", declared, installed, composerKey, strict, composerBuildOrLockHint)
}

// readComposerVendor walks vendor/<org>/<pkg>/composer.json reading the package
// name and installed version.
func readComposerVendor(vendorDir string) map[string]installedDep {
	orgs, err := os.ReadDir(vendorDir)
	if err != nil {
		return nil
	}
	out := map[string]installedDep{}
	add := func(pkgDir string) {
		data, err := os.ReadFile(filepath.Join(pkgDir, "composer.json"))
		if err != nil {
			return
		}
		var cj struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if err := json.Unmarshal(data, &cj); err != nil || cj.Name == "" || cj.Version == "" {
			return
		}
		k := composerKey(cj.Name)
		if _, ok := out[k]; !ok {
			out[k] = installedDep{Name: cj.Name, Version: strings.TrimPrefix(cj.Version, "v"), Dir: pkgDir}
		}
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
			if pkg.IsDir() {
				add(filepath.Join(orgDir, pkg.Name()))
			}
		}
	}
	return out
}
