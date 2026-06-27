package scan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func init() {
	gateRegistry["rubygems"] = gateSpec{
		gated:       func(t string) bool { return t == "Gemfile" },
		lockPresent: func(dir string) bool { return anySiblingExists(dir, []string{"Gemfile.lock"}) },
		fullyPinned: nil, // Gemfile specs are typically ranges (`~>`, `>=`)
		resolve:     ResolveGemsFromInstalled,
	}
}

// gemKey: rubygem names are case-sensitive and dashes are significant.
func gemKey(n string) string { return n }

func gemsBuildOrLockHint(relPath string) string {
	return fmt.Sprintf("%s has no Gemfile.lock and its gems are not installed: build the app (bundle install) or generate a lock file (bundle lock), then re-run the scan", relPath)
}

// rubyGemDirSplit splits a gem directory name "<gem>-<version>[-<platform>]" into
// name and version, reusing extractGemName for the name boundary and trimming any
// trailing platform suffix from the version.
func rubyGemDirSplit(stem string) (name, version string) {
	name = extractGemName(stem)
	rest := strings.TrimPrefix(stem, name+"-")
	if rest == stem || rest == "" {
		return name, ""
	}
	if i := strings.Index(rest, "-"); i >= 0 {
		rest = rest[:i] // drop platform suffix (e.g. "1.16.0-x86_64-linux")
	}
	return name, rest
}

// ResolveGemsFromInstalled resolves Gemfile deps from a project bundle
// (vendor/bundle, full transitive set) or the global gem home (declared-only).
func ResolveGemsFromInstalled(manifestPath, relPath string, declared []ScopedPackage, strict bool) ([]ScopedPackage, error) {
	projectDir := filepath.Dir(manifestPath)
	manifestDir := filepath.Dir(relPath)

	// Project: vendor/bundle/ruby/*/gems/<gem>-<ver>/
	projectGemDirs, _ := filepath.Glob(filepath.Join(projectDir, "vendor", "bundle", "ruby", "*", "gems"))
	if installed := readNameDashVersionDirs(projectGemDirs, rubyGemDirSplit, gemKey); len(installed) > 0 {
		return resolveFromProjectInstall(relPath, manifestDir, projectDir, "rubygems", declared, installed, gemKey, strict, gemsBuildOrLockHint)
	}

	// Global: $GEM_HOME/gems or ~/.gem/ruby/*/gems
	var globalDirs []string
	if v := os.Getenv("GEM_HOME"); v != "" {
		globalDirs = append(globalDirs, filepath.Join(v, "gems"))
	}
	if h := homeDir(); h != "" {
		if m, _ := filepath.Glob(filepath.Join(h, ".gem", "ruby", "*", "gems")); len(m) > 0 {
			globalDirs = append(globalDirs, m...)
		}
	}
	if installed := readNameDashVersionDirs(globalDirs, rubyGemDirSplit, gemKey); len(installed) > 0 {
		return resolveFromGlobalInstall(relPath, "rubygems", declared, installed, gemKey, strict, gemsBuildOrLockHint)
	}
	return nil, errors.New(gemsBuildOrLockHint(relPath))
}
