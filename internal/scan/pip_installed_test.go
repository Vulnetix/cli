package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makePyVenv creates a minimal project venv with the given name→version
// distributions as *.dist-info directories, and isolates the venv-discovery env.
func makePyVenv(t *testing.T, root string, dists map[string]string) {
	t.Helper()
	t.Setenv("VIRTUAL_ENV", "")
	t.Setenv("CONDA_PREFIX", "")
	t.Setenv("UV_PROJECT_ENVIRONMENT", "")
	sp := filepath.Join(root, ".venv", "lib", "python3.13", "site-packages")
	if err := os.MkdirAll(sp, 0o755); err != nil {
		t.Fatal(err)
	}
	writePyTestFile(t, filepath.Join(root, ".venv", "pyvenv.cfg"), "home = /usr\nversion_info = 3.13.0\n")
	for name, ver := range dists {
		di := filepath.Join(sp, name+"-"+ver+".dist-info")
		if err := os.MkdirAll(di, 0o755); err != nil {
			t.Fatal(err)
		}
		writePyTestFile(t, filepath.Join(di, "METADATA"), "Name: "+name+"\nVersion: "+ver+"\n")
	}
}

func TestRequirementsFullyLocked(t *testing.T) {
	cases := []struct {
		name string
		pkgs []ScopedPackage
		want bool
	}{
		{"exact pin", []ScopedPackage{{Name: "a", Version: "1.0", VersionSpec: "==1.0"}}, true},
		{"hashed", []ScopedPackage{{Name: "a", Checksums: []PackageChecksum{{Alg: "SHA-256", Value: "x"}}}}, true},
		{"range", []ScopedPackage{{Name: "a", Version: "1.0", VersionSpec: ">=1.0"}}, false},
		{"bare name", []ScopedPackage{{Name: "a"}}, false},
		{"empty", nil, false},
		{"mixed unpinned", []ScopedPackage{{Name: "a", Version: "1.0", VersionSpec: "==1.0"}, {Name: "b"}}, false},
	}
	for _, c := range cases {
		if got := RequirementsFullyLocked(c.pkgs); got != c.want {
			t.Errorf("%s: RequirementsFullyLocked = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPyLockfilePresent(t *testing.T) {
	dir := t.TempDir()
	if PyLockfilePresent(dir) {
		t.Error("empty dir reports a lock")
	}
	writePyTestFile(t, filepath.Join(dir, "uv.lock"), "version = 1\n")
	if !PyLockfilePresent(dir) {
		t.Error("uv.lock present but not detected")
	}
}

func TestReadInstalledPythonPackages(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{
		"attrs-25.3.0.dist-info",
		"jsonschema_specifications-2025.4.1.dist-info",
		"foo-1.0.egg-info",
	} {
		if err := os.MkdirAll(filepath.Join(dir, n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	m, err := readInstalledPythonPackages(dir)
	if err != nil {
		t.Fatal(err)
	}
	if m["attrs"].Version != "25.3.0" {
		t.Errorf("attrs = %+v", m["attrs"])
	}
	if m["jsonschema_specifications"].Version != "2025.4.1" {
		t.Errorf("jsonschema_specifications = %+v", m["jsonschema_specifications"])
	}
	if m["foo"].Version != "1.0" {
		t.Errorf("foo (egg-info) = %+v", m["foo"])
	}
}

// Confident requirements file resolved from a project venv: declared packages
// are manifest provenance, venv-only packages are installed transitives.
func TestResolvePython_VenvResolvesWithProvenance(t *testing.T) {
	root := t.TempDir()
	writePyTestFile(t, filepath.Join(root, "requirements.txt"), "flask\n")
	makePyVenv(t, root, map[string]string{"flask": "2.3.0", "werkzeug": "2.3.0"})

	declared := []ScopedPackage{{Name: "flask", Ecosystem: "pypi", Scope: ScopeProduction, IsDirect: true}}
	got, err := ResolvePythonRequirementsFromSitePackages(
		filepath.Join(root, "requirements.txt"), "requirements.txt", declared, true)
	if err != nil {
		t.Fatal(err)
	}

	flask, ok := findPkg(got, "flask")
	if !ok {
		t.Fatal("flask missing")
	}
	if flask.Version != "2.3.0" || !flask.IsDirect || flask.SourceType != SourceTypeManifest || flask.InstalledPath != "" {
		t.Errorf("flask provenance wrong: %+v", flask)
	}
	wk, ok := findPkg(got, "werkzeug")
	if !ok {
		t.Fatal("werkzeug (transitive) missing")
	}
	if wk.IsDirect || wk.SourceType != SourceTypeInstalled || wk.InstalledPath == "" {
		t.Errorf("werkzeug provenance wrong: %+v", wk)
	}
}

// A confident file with a declared dep absent from the env is a fatal error with
// the build-or-lock remediation.
func TestResolvePython_ConfidentMissingErrors(t *testing.T) {
	root := t.TempDir()
	writePyTestFile(t, filepath.Join(root, "requirements.txt"), "flask>=2.0\n")
	makePyVenv(t, root, map[string]string{"requests": "2.0"}) // flask NOT installed

	declared := []ScopedPackage{{Name: "flask", VersionSpec: ">=2.0", Ecosystem: "pypi"}}
	_, err := ResolvePythonRequirementsFromSitePackages(
		filepath.Join(root, "requirements.txt"), "requirements.txt", declared, true)
	if err == nil {
		t.Fatal("expected error for a missing confident dependency")
	}
	for _, want := range []string{"build the app", "generate a lock file", "flask"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q: %v", want, err)
		}
	}
}

// A tentative file is confirmed when ANY declared name is installed (user choice).
func TestResolvePython_TentativeAnyMatchConfirms(t *testing.T) {
	root := t.TempDir()
	writePyTestFile(t, filepath.Join(root, "names.lst"), "flask\nnotapkg\n")
	makePyVenv(t, root, map[string]string{"flask": "2.3.0"})

	declared := []ScopedPackage{{Name: "flask"}, {Name: "notapkg"}}
	got, err := ResolvePythonRequirementsFromSitePackages(
		filepath.Join(root, "names.lst"), "names.lst", declared, false)
	if err != nil {
		t.Fatalf("tentative file with 1 installed match should resolve: %v", err)
	}
	if _, ok := findPkg(got, "flask"); !ok {
		t.Error("flask should be resolved")
	}
}

// A tentative file with no installed matches is disregarded (resolver errors so
// the caller drops it).
func TestResolvePython_TentativeNoMatchDropped(t *testing.T) {
	root := t.TempDir()
	writePyTestFile(t, filepath.Join(root, "names.lst"), "alpha\nbeta\n")
	makePyVenv(t, root, map[string]string{"flask": "2.3.0"})

	declared := []ScopedPackage{{Name: "alpha"}, {Name: "beta"}}
	if _, err := ResolvePythonRequirementsFromSitePackages(
		filepath.Join(root, "names.lst"), "names.lst", declared, false); err == nil {
		t.Fatal("tentative file with no installed match should error (be dropped)")
	}
}
