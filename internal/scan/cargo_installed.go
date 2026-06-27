package scan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

func init() {
	gateRegistry["cargo"] = gateSpec{
		gated:       func(t string) bool { return t == "Cargo.toml" },
		lockPresent: func(dir string) bool { return anySiblingExists(dir, []string{"Cargo.lock"}) },
		fullyPinned: nil, // Cargo.toml is caret-by-default (e.g. `serde = "1"`)
		resolve:     ResolveCargoFromInstalled,
	}
}

// cargoKey normalises a crate name (case-insensitive; '-' and '_' equivalent).
func cargoKey(n string) string { return strings.ToLower(strings.ReplaceAll(n, "-", "_")) }

func cargoBuildOrLockHint(relPath string) string {
	return fmt.Sprintf("%s has no Cargo.lock and its dependencies are not vendored: build the app (cargo build / cargo fetch) or generate a lock file (cargo generate-lockfile), then re-run the scan", relPath)
}

// ResolveCargoFromInstalled resolves Cargo.toml deps from a project `vendor/`
// directory (full transitive set) or, failing that, the global cargo registry
// cache (declared-only).
func ResolveCargoFromInstalled(manifestPath, relPath string, declared []ScopedPackage, strict bool) ([]ScopedPackage, error) {
	projectDir := filepath.Dir(manifestPath)
	manifestDir := filepath.Dir(relPath)

	if installed := readCargoVendor(filepath.Join(projectDir, "vendor")); len(installed) > 0 {
		return resolveFromProjectInstall(relPath, manifestDir, projectDir, "cargo", declared, installed, cargoKey, strict, cargoBuildOrLockHint)
	}
	if installed := readCargoRegistry(); len(installed) > 0 {
		return resolveFromGlobalInstall(relPath, "cargo", declared, installed, cargoKey, strict, cargoBuildOrLockHint)
	}
	return nil, errors.New(cargoBuildOrLockHint(relPath))
}

// readCargoVendor reads `vendor/<crate>/Cargo.toml` for the [package] version.
func readCargoVendor(vendorDir string) map[string]installedDep {
	entries, err := os.ReadDir(vendorDir)
	if err != nil {
		return nil
	}
	out := map[string]installedDep{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(vendorDir, e.Name(), "Cargo.toml"))
		if err != nil {
			continue
		}
		var m struct {
			Package struct {
				Name    string `toml:"name"`
				Version string `toml:"version"`
			} `toml:"package"`
		}
		if _, err := toml.Decode(string(data), &m); err != nil || m.Package.Version == "" {
			continue
		}
		name := m.Package.Name
		if name == "" {
			name = e.Name()
		}
		k := cargoKey(name)
		if _, ok := out[k]; !ok {
			out[k] = installedDep{Name: name, Version: m.Package.Version, Dir: filepath.Join(vendorDir, e.Name())}
		}
	}
	return out
}

// readCargoRegistry reads the global cargo registry source cache
// ($CARGO_HOME|~/.cargo)/registry/src/*/<crate>-<version>/.
func readCargoRegistry() map[string]installedDep {
	cargoHome := os.Getenv("CARGO_HOME")
	if cargoHome == "" {
		if h := homeDir(); h != "" {
			cargoHome = filepath.Join(h, ".cargo")
		}
	}
	if cargoHome == "" {
		return nil
	}
	srcDirs, _ := filepath.Glob(filepath.Join(cargoHome, "registry", "src", "*"))
	return readNameDashVersionDirs(srcDirs, splitNameVersion, cargoKey)
}
