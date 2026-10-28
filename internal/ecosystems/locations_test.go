package ecosystems

import (
	"os"
	"path/filepath"
	"testing"
)

func mkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func writeFile(t *testing.T, path string) {
	t.Helper()
	mkdirAll(t, filepath.Dir(path))
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func slugForPath(targets []Target, abs string) (Target, bool) {
	for _, tt := range targets {
		if tt.Path == abs {
			return tt, true
		}
	}
	return Target{}, false
}

func TestResolveProjectDirs(t *testing.T) {
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "node_modules", "left-pad"))
	mkdirAll(t, filepath.Join(root, ".venv", "lib", "python3.12", "site-packages"))

	targets := Resolve(root, Scope{})

	nm := filepath.Join(root, "node_modules")
	if tt, ok := slugForPath(targets, nm); !ok {
		t.Fatalf("node_modules not resolved; got %+v", targets)
	} else if tt.EngineSlug != "npm" || tt.Ecosystem != "javascript" {
		t.Fatalf("node_modules wrong mapping: %+v", tt)
	}

	venv := filepath.Join(root, ".venv")
	if tt, ok := slugForPath(targets, venv); !ok {
		t.Fatalf(".venv not resolved; got %+v", targets)
	} else if tt.EngineSlug != "pypi" {
		t.Fatalf(".venv wrong slug: %+v", tt)
	}
}

func TestResolveVendorManifestGating(t *testing.T) {
	// A bare vendor/ with no manifest must NOT be resolved (ambiguous Go/PHP/Rust).
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "vendor", "pkg"))

	if targets := Resolve(root, Scope{}); len(targets) != 0 {
		t.Fatalf("expected no targets for bare vendor/, got %+v", targets)
	}

	// With go.mod present, vendor/ is attributed to Go.
	writeFile(t, filepath.Join(root, "go.mod"))
	targets := Resolve(root, Scope{})
	v := filepath.Join(root, "vendor")
	tt, ok := slugForPath(targets, v)
	if !ok {
		t.Fatalf("vendor not resolved with go.mod; got %+v", targets)
	}
	if tt.EngineSlug != "go" {
		t.Fatalf("vendor should map to go, got %q", tt.EngineSlug)
	}
}

func TestResolveDedupesByPath(t *testing.T) {
	// composer.json AND go.mod both present: vendor/ must appear exactly once.
	root := t.TempDir()
	mkdirAll(t, filepath.Join(root, "vendor", "x"))
	writeFile(t, filepath.Join(root, "go.mod"))
	writeFile(t, filepath.Join(root, "composer.json"))

	count := 0
	for _, tt := range Resolve(root, Scope{}) {
		if tt.Path == filepath.Join(root, "vendor") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected vendor resolved once, got %d", count)
	}
}

func TestResolveSkipsMissing(t *testing.T) {
	root := t.TempDir() // empty
	if targets := Resolve(root, Scope{}); len(targets) != 0 {
		t.Fatalf("expected no targets in empty root, got %+v", targets)
	}
}

func TestResolveIncludeHome(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	// GOMODCACHE override should be picked up as a go user dir.
	gomod := filepath.Join(home, "gomodcache")
	mkdirAll(t, gomod)
	t.Setenv("GOMODCACHE", gomod)

	withHome := Resolve(root, Scope{Home: true})
	if _, ok := slugForPath(withHome, gomod); !ok {
		t.Fatalf("GOMODCACHE not resolved with includeHome; got %+v", withHome)
	}
	for _, tt := range withHome {
		if tt.Path == gomod && !tt.UserScoped {
			t.Fatalf("home cache should be UserScoped: %+v", tt)
		}
	}

	// Without includeHome, the home cache must not appear.
	if _, ok := slugForPath(Resolve(root, Scope{}), gomod); ok {
		t.Fatalf("home cache leaked without includeHome")
	}
}

func TestScanSkipDirsDoesNotPruneNodeModules(t *testing.T) {
	for _, d := range ScanSkipDirs() {
		if d == "node_modules" || d == "vendor" {
			t.Fatalf("ScanSkipDirs must not prune %q — it is a scan target", d)
		}
	}
}

// fakeSystem lays out a mounted image: distro and global installs, two accounts'
// caches, and a merged-/usr symlink written the way the image wrote it.
func fakeSystem(t *testing.T) string {
	t.Helper()
	sys := t.TempDir()
	mkdirAll(t, filepath.Join(sys, "usr", "lib", "python3", "dist-packages", "requests"))
	mkdirAll(t, filepath.Join(sys, "usr", "local", "lib", "python3.11", "site-packages", "flask"))
	mkdirAll(t, filepath.Join(sys, "usr", "lib", "node_modules", "npm"))
	mkdirAll(t, filepath.Join(sys, "var", "lib", "gems", "3.1.0", "gems"))
	mkdirAll(t, filepath.Join(sys, "home", "alice", ".npm"))
	mkdirAll(t, filepath.Join(sys, "home", "bob", ".cargo", "registry"))
	mkdirAll(t, filepath.Join(sys, "root", "go", "pkg", "mod"))
	mkdirAll(t, filepath.Join(sys, "usr", "bin"))
	mkdirAll(t, filepath.Join(sys, "opt", "app"))
	if err := os.Symlink("/usr/bin", filepath.Join(sys, "bin")); err != nil {
		t.Fatal(err)
	}
	return sys
}

func TestResolveSystemScope(t *testing.T) {
	sys := fakeSystem(t)
	project := t.TempDir()

	if targets := Resolve(project, Scope{SystemRoot: sys}); len(targets) != 0 {
		t.Fatalf("system dirs must need --include-system, got %+v", targets)
	}

	targets := Resolve(project, Scope{System: true, SystemRoot: sys})
	want := map[string]string{
		filepath.Join(sys, "usr", "lib", "python3", "dist-packages"):             "pypi",
		filepath.Join(sys, "usr", "local", "lib", "python3.11", "site-packages"): "pypi",
		filepath.Join(sys, "usr", "lib", "node_modules"):                         "npm",
		filepath.Join(sys, "var", "lib", "gems", "3.1.0"):                        "rubygems",
		filepath.Join(sys, "home", "alice", ".npm"):                              "npm",
		filepath.Join(sys, "home", "bob", ".cargo", "registry"):                  "cargo",
		filepath.Join(sys, "root", "go", "pkg", "mod"):                           "go",
	}
	for path, slug := range want {
		tt, ok := slugForPath(targets, path)
		if !ok {
			t.Errorf("%s not resolved; got %+v", path, targets)
			continue
		}
		if tt.EngineSlug != slug || !tt.SystemScoped {
			t.Errorf("%s: got slug %q systemScoped %v", path, tt.EngineSlug, tt.SystemScoped)
		}
	}
	// Labels are the path on the scanned system, not where it is mounted.
	if tt, _ := slugForPath(targets, filepath.Join(sys, "home", "alice", ".npm")); tt.Label != "/home/alice/.npm" {
		t.Errorf("label = %q, want /home/alice/.npm", tt.Label)
	}
}

func TestSystemBinaryDirsStayInsideRoot(t *testing.T) {
	sys := fakeSystem(t)
	dirs := SystemBinaryDirs(sys)
	// /bin -> /usr/bin resolves inside the image and is reported once.
	var usrBin int
	for _, d := range dirs {
		if d == filepath.Join(sys, "usr", "bin") {
			usrBin++
		}
		if rel, err := filepath.Rel(sys, d); err != nil || startsWithDotDot(rel) {
			t.Errorf("%s escapes the system root", d)
		}
	}
	if usrBin != 1 {
		t.Errorf("usr/bin reported %d times in %v", usrBin, dirs)
	}

	// A link that climbs out of the image is dropped, not followed on the host.
	if err := os.Symlink("../../../../../../etc", filepath.Join(sys, "sbin")); err != nil {
		t.Fatal(err)
	}
	for _, d := range SystemBinaryDirs(sys) {
		if filepath.Base(d) == "etc" {
			t.Errorf("followed an escaping link to %s", d)
		}
	}
}
