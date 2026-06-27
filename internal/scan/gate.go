package scan

import (
	"os"
	"path/filepath"
)

// gateSpec describes the build-or-lock gate for one ecosystem. A manifest that
// declares dependencies but has no usable lock must resolve those dependencies
// from the installed environment, or the scan stops and tells the user to build
// the app / generate a lock file. Lock files and fully-pinned manifests are never
// gated (they are scannable as-is).
type gateSpec struct {
	// gated reports whether a manifest type participates in this gate.
	gated func(manifestType string) bool
	// lockPresent reports whether a sibling lock exists in the manifest's dir, in
	// which case the lock is scanned and the gate is a no-op.
	lockPresent func(manifestDir string) bool
	// fullyPinned reports whether the parsed packages are already pinned enough to
	// scan without resolving (exact versions / checksums). nil means "never
	// pre-satisfied" — used for caret-by-default manifests whose bare specs would
	// fool IsVersionSpecPinned.
	fullyPinned func(pkgs []ScopedPackage) bool
	// resolve resolves declared packages to exact installed versions (and, from a
	// project-scoped install dir, adds installed transitives with provenance), or
	// returns a build-or-lock error. strict=false (a tentative detection) keeps
	// whatever resolves; strict=true requires the full declared set.
	resolve func(manifestPath, relPath string, declared []ScopedPackage, strict bool) ([]ScopedPackage, error)
}

// gateRegistry is keyed by the detector ecosystem slug (ManifestInfo.Ecosystem).
var gateRegistry = map[string]gateSpec{
	"npm": {
		gated:       func(t string) bool { return t == "package.json" },
		lockPresent: func(dir string) bool { return anySiblingExists(dir, npmLockfileNames) },
		// package.json deps are ranges; always resolve when there is no lockfile.
		fullyPinned: nil,
		resolve: func(manifestPath, relPath string, declared []ScopedPackage, _ bool) ([]ScopedPackage, error) {
			return ResolveNpmPackageJSONFromNodeModules(manifestPath, relPath, declared)
		},
	},
	"pypi": {
		gated:       IsPythonGatedManifest,
		lockPresent: PyLockfilePresent,
		fullyPinned: RequirementsFullyLocked,
		resolve:     ResolvePythonRequirementsFromSitePackages,
	},
}

// ApplyBuildOrLockGate runs the build-or-lock gate for one parsed manifest.
// It returns the (possibly resolved) package set; dropFile=true when a tentative
// file could not be confirmed and the caller should skip it; and a fatal err when
// a confident manifest cannot be resolved (caller should return it → exit).
func ApplyBuildOrLockGate(eco, manifestType, manifestPath, relPath string, confident bool, pkgs []ScopedPackage) (resolved []ScopedPackage, dropFile bool, err error) {
	spec, ok := gateRegistry[eco]
	if !ok || len(pkgs) == 0 || spec.gated == nil || !spec.gated(manifestType) {
		return pkgs, false, nil
	}
	if spec.fullyPinned != nil && spec.fullyPinned(pkgs) {
		return pkgs, false, nil // already scannable at exact versions
	}
	if spec.lockPresent != nil && spec.lockPresent(filepath.Dir(manifestPath)) {
		return pkgs, false, nil // a sibling lock will be scanned
	}
	out, rerr := spec.resolve(manifestPath, relPath, pkgs, confident)
	if rerr != nil {
		if confident {
			return nil, false, rerr // fatal: build the app or generate a lock file
		}
		return nil, true, rerr // tentative: drop the file, no error
	}
	return out, false, nil
}

// allVersionsPinned is the generic fully-pinned check for exact-version manifests
// (e.g. pom.xml, *.csproj): every package carries a non-empty exact version.
func allVersionsPinned(pkgs []ScopedPackage) bool {
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

// anySiblingExists reports whether any of names exists as a regular file in dir.
func anySiblingExists(dir string, names []string) bool {
	for _, name := range names {
		if info, err := os.Stat(filepath.Join(dir, name)); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}
