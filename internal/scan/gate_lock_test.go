package scan

import (
	"os"
	"path/filepath"
	"testing"
)

// A manifest range is not an installed version. With a lockfile beside it the lock
// supplies the versions, so the manifest's ranges must not be queried as if they
// were installed: `gem 'thor', '~> 1.2'` was reported as thor 1.2 while
// Gemfile.lock pinned 1.5.0, and eslint "^7" was reported as eslint 7.
func TestGateDropsManifestRangesWhenALockfileSuppliesTheVersions(t *testing.T) {
	cases := []struct {
		eco, typ, manifest, lock string
	}{
		{"rubygems", "Gemfile", "Gemfile", "Gemfile.lock"},
		{"npm", "package.json", "package.json", "package-lock.json"},
	}
	for _, c := range cases {
		dir := t.TempDir()
		for _, f := range []string{c.manifest, c.lock} {
			if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		pkgs := []ScopedPackage{
			{Name: "ranged", Version: "1.2", VersionSpec: "~> 1.2"},
			{Name: "caret", Version: "7", VersionSpec: "^7"},
			{Name: "pinned", Version: "2.0.1", VersionSpec: "2.0.1"},
		}
		got, drop, err := ApplyBuildOrLockGate(c.eco, c.typ, filepath.Join(dir, c.manifest), c.manifest, true, pkgs)
		if err != nil || drop {
			t.Fatalf("%s: err=%v drop=%v", c.eco, err, drop)
		}
		if len(got) != 1 || got[0].Name != "pinned" {
			t.Errorf("%s: only the exact pin should survive beside a lockfile, got %+v", c.eco, got)
		}
	}
}

// A .csproj under central package management carries no version, and its pins live in a
// Directory.Packages.props above it. It is not an unrestored project.
func TestNugetProjectBesideCentralPackagesIsNotUnrestored(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "src", "App")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{filepath.Join(root, "Directory.Packages.props"), filepath.Join(sub, "App.csproj")} {
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_, drop, err := ApplyBuildOrLockGate("nuget", "*.csproj", filepath.Join(sub, "App.csproj"), "src/App/App.csproj", true,
		[]ScopedPackage{{Name: "Serilog"}})
	if err != nil || drop {
		t.Fatalf("a project under central package management must not be reported unrestored: err=%v drop=%v", err, drop)
	}
}

// Package.swift `from: "1.24.0"` is a minimum, so without a Package.resolved the manifest
// cannot be scanned at an exact version; an `exact:` pin can.
func TestSwiftFromRangeNeedsPackageResolved(t *testing.T) {
	dir := t.TempDir()
	m := filepath.Join(dir, "Package.swift")
	if err := os.WriteFile(m, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, drop, err := ApplyBuildOrLockGate("swift", "Package.swift", m, "Package.swift", true,
		[]ScopedPackage{{Name: "swift-nio", Version: "2.101.3", VersionSpec: ">=2.101.3"}})
	if err == nil && !drop {
		t.Fatal("a from: range with no Package.resolved must not be scanned as an exact version")
	}
	got, drop, err := ApplyBuildOrLockGate("swift", "Package.swift", m, "Package.swift", true,
		[]ScopedPackage{{Name: "swift-log", Version: "1.6.0", VersionSpec: "1.6.0"}})
	if err != nil || drop || len(got) != 1 {
		t.Fatalf("an exact: pin is scannable, got %v drop=%v err=%v", got, drop, err)
	}
}
