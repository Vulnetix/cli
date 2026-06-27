package scan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func init() {
	gateRegistry["hex"] = gateSpec{
		gated:       func(t string) bool { return t == "mix.exs" },
		lockPresent: func(dir string) bool { return anySiblingExists(dir, []string{"mix.lock"}) },
		fullyPinned: nil, // mix.exs uses ranges (`~>`)
		resolve:     ResolveHexFromInstalled,
	}
}

// hexKey: Hex package names are lower-case atoms.
func hexKey(n string) string { return strings.ToLower(n) }

func hexBuildOrLockHint(relPath string) string {
	return fmt.Sprintf("%s has no mix.lock and its deps are not fetched: build the app (mix deps.get) or commit mix.lock, then re-run the scan", relPath)
}

var hexMetaVersionRe = regexp.MustCompile(`\{<<"version">>,<<"([^"]+)">>\}`)

// ResolveHexFromInstalled resolves mix.exs deps from the project `deps/` tree
// (full transitive set; version from each dep's hex_metadata.config).
func ResolveHexFromInstalled(manifestPath, relPath string, declared []ScopedPackage, strict bool) ([]ScopedPackage, error) {
	projectDir := filepath.Dir(manifestPath)
	manifestDir := filepath.Dir(relPath)

	installed := readHexDeps(filepath.Join(projectDir, "deps"))
	if len(installed) == 0 {
		return nil, errors.New(hexBuildOrLockHint(relPath))
	}
	return resolveFromProjectInstall(relPath, manifestDir, projectDir, "hex", declared, installed, hexKey, strict, hexBuildOrLockHint)
}

// readHexDeps reads deps/<dep>/hex_metadata.config for each fetched dependency.
func readHexDeps(depsDir string) map[string]installedDep {
	entries, err := os.ReadDir(depsDir)
	if err != nil {
		return nil
	}
	out := map[string]installedDep{}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		depDir := filepath.Join(depsDir, e.Name())
		data, err := os.ReadFile(filepath.Join(depDir, "hex_metadata.config"))
		if err != nil {
			continue // git/path deps have no hex_metadata.config
		}
		m := hexMetaVersionRe.FindSubmatch(data)
		if m == nil {
			continue
		}
		k := hexKey(e.Name())
		if _, ok := out[k]; !ok {
			out[k] = installedDep{Name: e.Name(), Version: string(m[1]), Dir: depDir}
		}
	}
	return out
}
