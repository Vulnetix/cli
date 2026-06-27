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
	gateRegistry["pub"] = gateSpec{
		gated:       func(t string) bool { return t == "pubspec.yaml" },
		lockPresent: func(dir string) bool { return anySiblingExists(dir, []string{"pubspec.lock"}) },
		fullyPinned: nil, // pubspec.yaml uses caret ranges
		resolve:     ResolvePubFromInstalled,
	}
}

// pubKey: Dart package names are lower-case snake_case.
func pubKey(n string) string { return strings.ToLower(n) }

func pubBuildOrLockHint(relPath string) string {
	return fmt.Sprintf("%s has no pubspec.lock and its packages are not resolved: build the app (dart pub get / flutter pub get) or commit pubspec.lock, then re-run the scan", relPath)
}

// ResolvePubFromInstalled resolves pubspec.yaml deps from the project's resolved
// set (.dart_tool/package_config.json, full) or the global pub-cache (declared-only).
func ResolvePubFromInstalled(manifestPath, relPath string, declared []ScopedPackage, strict bool) ([]ScopedPackage, error) {
	projectDir := filepath.Dir(manifestPath)
	manifestDir := filepath.Dir(relPath)

	if installed := readDartPackageConfig(filepath.Join(projectDir, ".dart_tool", "package_config.json")); len(installed) > 0 {
		return resolveFromProjectInstall(relPath, manifestDir, projectDir, "pub", declared, installed, pubKey, strict, pubBuildOrLockHint)
	}

	pubCache := os.Getenv("PUB_CACHE")
	if pubCache == "" {
		if h := homeDir(); h != "" {
			pubCache = filepath.Join(h, ".pub-cache")
		}
	}
	hostedDirs, _ := filepath.Glob(filepath.Join(pubCache, "hosted", "*"))
	if installed := readNameDashVersionDirs(hostedDirs, splitNameVersion, pubKey); len(installed) > 0 {
		return resolveFromGlobalInstall(relPath, "pub", declared, installed, pubKey, strict, pubBuildOrLockHint)
	}
	return nil, errors.New(pubBuildOrLockHint(relPath))
}

// readDartPackageConfig parses .dart_tool/package_config.json, taking each
// package's name and the version encoded in its rootUri ("<name>-<version>").
func readDartPackageConfig(path string) map[string]installedDep {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var cfg struct {
		Packages []struct {
			Name    string `json:"name"`
			RootURI string `json:"rootUri"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	out := map[string]installedDep{}
	for _, p := range cfg.Packages {
		if p.Name == "" {
			continue
		}
		dir := strings.TrimPrefix(p.RootURI, "file://")
		_, ver := splitNameVersion(filepath.Base(dir))
		if ver == "" {
			continue // path/sdk/relative dep (e.g. the project itself) — no pinned version
		}
		k := pubKey(p.Name)
		if _, ok := out[k]; !ok {
			out[k] = installedDep{Name: p.Name, Version: ver, Dir: dir}
		}
	}
	return out
}
