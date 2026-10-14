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
