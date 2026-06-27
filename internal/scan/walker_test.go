package scan

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWalkForScanFiles_PrunesEcosystemInstallDirs asserts the manifest walker
// never descends into ecosystem-linked install/build dirs, so a foreign manifest
// bundled inside one (a package.json shipped inside a pypi package's
// site-packages) is not mis-attributed — while top-level manifests of any
// ecosystem are still discovered (polyglot repos are not language-gated).
func TestWalkForScanFiles_PrunesEcosystemInstallDirs(t *testing.T) {
	root := t.TempDir()

	mustWrite := func(rel string) {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		if err := os.WriteFile(full, []byte("{}\n"), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	// Legitimate top-level manifests — both must be discovered.
	mustWrite("requirements.txt")
	mustWrite("package.json")

	// Foreign manifests bundled inside ecosystem install dirs — must be pruned.
	mustWrite("venv/lib/python3.11/site-packages/foo/package.json")
	mustWrite("node_modules/bar/package.json")
	mustWrite("node_modules/bar/test/fixtures/requirements.txt")

	detected, err := WalkForScanFiles(WalkOptions{RootPath: root, MaxDepth: 12})
	if err != nil {
		t.Fatalf("WalkForScanFiles: %v", err)
	}

	got := map[string]bool{}
	for _, f := range detected {
		if f.FileType != FileTypeManifest {
			continue
		}
		rel, _ := filepath.Rel(root, f.Path)
		got[filepath.ToSlash(rel)] = true
	}

	wantPresent := []string{"requirements.txt", "package.json"}
	for _, w := range wantPresent {
		if !got[w] {
			t.Errorf("expected top-level manifest %q to be detected; got %v", w, got)
		}
	}

	wantAbsent := []string{
		"venv/lib/python3.11/site-packages/foo/package.json",
		"node_modules/bar/package.json",
		"node_modules/bar/test/fixtures/requirements.txt",
	}
	for _, w := range wantAbsent {
		if got[w] {
			t.Errorf("manifest inside an install dir must be pruned, but %q was detected", w)
		}
	}
}
