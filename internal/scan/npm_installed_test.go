package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveNpmPackageJSONFromNodeModules(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "app")
	writeNpmPackage(t, filepath.Join(project, "package.json"), `{
		"dependencies": {"direct": "^1.0.0"},
		"devDependencies": {"@scope/dev": "~2.0.0"}
	}`)
	writeNpmPackage(t, filepath.Join(project, "node_modules", "direct", "package.json"), `{
		"name": "direct",
		"version": "1.2.3",
		"dependencies": {"transitive": "^3.0.0"}
	}`)
	writeNpmPackage(t, filepath.Join(project, "node_modules", "@scope", "dev", "package.json"), `{
		"name": "@scope/dev",
		"version": "2.4.0"
	}`)
	writeNpmPackage(t, filepath.Join(project, "node_modules", "transitive", "package.json"), `{
		"name": "transitive",
		"version": "3.1.4"
	}`)

	directPkgs, err := parsePackageJSONScoped(mustRead(t, filepath.Join(project, "package.json")), filepath.Join(project, "package.json"))
	if err != nil {
		t.Fatalf("parse package.json: %v", err)
	}
	got, err := ResolveNpmPackageJSONFromNodeModules(filepath.Join(project, "package.json"), "app/package.json", directPkgs)
	if err != nil {
		t.Fatalf("ResolveNpmPackageJSONFromNodeModules returned error: %v", err)
	}

	assertPkg(t, got, "direct", "1.2.3", "^1.0.0", true)
	assertPkg(t, got, "@scope/dev", "2.4.0", "~2.0.0", true)
	assertPkg(t, got, "transitive", "3.1.4", "", false)

	// Discovery-source provenance: declared deps are "manifest" with no install
	// path; the transitive found only in node_modules is "installed" and carries
	// its root-relative install location for remediation.
	assertProvenance(t, got, "direct", SourceTypeManifest, "")
	assertProvenance(t, got, "transitive", SourceTypeInstalled, "app/node_modules/transitive")

	graph := BuildNpmDepGraph(got, nil)
	installed, err := readNpmInstalledPackages(filepath.Join(project, "node_modules"))
	if err != nil {
		t.Fatalf("read installed packages: %v", err)
	}
	populateNpmGraphFromInstalled(graph, installed)
	if !graph.IsDirect("direct") {
		t.Fatalf("direct package was not classified as direct")
	}
	if graph.IsDirect("transitive") {
		t.Fatalf("transitive package was classified as direct")
	}
	path := graph.FindPath("transitive")
	if len(path) != 2 || path[0] != "direct" || path[1] != "transitive" {
		t.Fatalf("FindPath(transitive) = %#v, want [direct transitive]", path)
	}
}

func TestResolveNpmPackageJSONFromNodeModulesRequiresNodeModules(t *testing.T) {
	root := t.TempDir()
	writeNpmPackage(t, filepath.Join(root, "package.json"), `{"dependencies": {"direct": "^1.0.0"}}`)
	directPkgs, err := parsePackageJSONScoped(mustRead(t, filepath.Join(root, "package.json")), filepath.Join(root, "package.json"))
	if err != nil {
		t.Fatalf("parse package.json: %v", err)
	}
	if _, err := ResolveNpmPackageJSONFromNodeModules(filepath.Join(root, "package.json"), "package.json", directPkgs); err == nil {
		t.Fatalf("expected missing node_modules error")
	}
}

func TestResolveNpmPackageJSONFromNodeModulesRequiresDirectPackages(t *testing.T) {
	root := t.TempDir()
	writeNpmPackage(t, filepath.Join(root, "package.json"), `{"dependencies": {"direct": "^1.0.0"}}`)
	if err := os.MkdirAll(filepath.Join(root, "node_modules"), 0o755); err != nil {
		t.Fatalf("mkdir node_modules: %v", err)
	}
	directPkgs, err := parsePackageJSONScoped(mustRead(t, filepath.Join(root, "package.json")), filepath.Join(root, "package.json"))
	if err != nil {
		t.Fatalf("parse package.json: %v", err)
	}
	if _, err := ResolveNpmPackageJSONFromNodeModules(filepath.Join(root, "package.json"), "package.json", directPkgs); err == nil {
		t.Fatalf("expected missing direct package error")
	}
}

// TestNpmLockfilePresent asserts each npm-family lockfile is recognised as a
// sibling of package.json, and that a bare package.json reports none.
func TestNpmLockfilePresent(t *testing.T) {
	for _, lock := range []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml"} {
		t.Run(lock, func(t *testing.T) {
			dir := t.TempDir()
			writeNpmPackage(t, filepath.Join(dir, "package.json"), `{"dependencies": {"direct": "^1.0.0"}}`)
			if NpmLockfilePresent(filepath.Join(dir, "package.json")) {
				t.Fatalf("no lockfile written yet, but NpmLockfilePresent reported one")
			}
			writeNpmPackage(t, filepath.Join(dir, lock), "")
			if !NpmLockfilePresent(filepath.Join(dir, "package.json")) {
				t.Fatalf("%s present but NpmLockfilePresent reported none", lock)
			}
		})
	}
}

// TestResolveNpmPackageJSONFromNodeModules_NoLockfileNoNodeModules verifies the
// exit message when a package.json has neither a lockfile nor node_modules: it
// must tell the user to build the app or generate a lock file.
func TestResolveNpmPackageJSONFromNodeModules_NoLockfileNoNodeModules(t *testing.T) {
	root := t.TempDir()
	writeNpmPackage(t, filepath.Join(root, "package.json"), `{"dependencies": {"direct": "^1.0.0"}}`)
	directPkgs, err := parsePackageJSONScoped(mustRead(t, filepath.Join(root, "package.json")), filepath.Join(root, "package.json"))
	if err != nil {
		t.Fatalf("parse package.json: %v", err)
	}

	_, err = ResolveNpmPackageJSONFromNodeModules(filepath.Join(root, "package.json"), "package.json", directPkgs)
	if err == nil {
		t.Fatalf("expected an error when no lockfile and no node_modules exist")
	}
	assertBuildOrLockMessage(t, err)
}

// TestResolveNpmPackageJSONFromNodeModules_IncompleteNodeModules verifies that a
// node_modules missing a declared (non-optional) dependency triggers the same
// build-or-lock exit, and names the missing package.
func TestResolveNpmPackageJSONFromNodeModules_IncompleteNodeModules(t *testing.T) {
	root := t.TempDir()
	writeNpmPackage(t, filepath.Join(root, "package.json"), `{
		"dependencies": {"present": "^1.0.0", "absent": "^2.0.0"}
	}`)
	// Only one of the two declared deps is actually installed.
	writeNpmPackage(t, filepath.Join(root, "node_modules", "present", "package.json"), `{"name": "present", "version": "1.2.3"}`)

	directPkgs, err := parsePackageJSONScoped(mustRead(t, filepath.Join(root, "package.json")), filepath.Join(root, "package.json"))
	if err != nil {
		t.Fatalf("parse package.json: %v", err)
	}

	_, err = ResolveNpmPackageJSONFromNodeModules(filepath.Join(root, "package.json"), "package.json", directPkgs)
	if err == nil {
		t.Fatalf("expected an error when node_modules is missing a declared dependency")
	}
	assertBuildOrLockMessage(t, err)
	if !strings.Contains(err.Error(), "absent") {
		t.Errorf("error should name the missing package %q; got: %v", "absent", err)
	}
	if strings.Contains(err.Error(), "present") && !strings.Contains(err.Error(), "absent, ") {
		// "present" must not be reported as missing.
		if strings.Contains(err.Error(), "missing declared dependencies: present") {
			t.Errorf("installed package %q reported as missing; got: %v", "present", err)
		}
	}
}

// TestResolveNpmPackageJSONFromNodeModules_OptionalDepAbsentOK verifies that a
// declared optionalDependency that is not installed does NOT trigger the exit —
// npm allows optional deps to be absent (e.g. platform-specific binaries).
func TestResolveNpmPackageJSONFromNodeModules_OptionalDepAbsentOK(t *testing.T) {
	root := t.TempDir()
	writeNpmPackage(t, filepath.Join(root, "package.json"), `{
		"dependencies": {"present": "^1.0.0"},
		"optionalDependencies": {"fsevents": "^2.0.0"}
	}`)
	writeNpmPackage(t, filepath.Join(root, "node_modules", "present", "package.json"), `{"name": "present", "version": "1.2.3"}`)

	directPkgs, err := parsePackageJSONScoped(mustRead(t, filepath.Join(root, "package.json")), filepath.Join(root, "package.json"))
	if err != nil {
		t.Fatalf("parse package.json: %v", err)
	}

	got, err := ResolveNpmPackageJSONFromNodeModules(filepath.Join(root, "package.json"), "package.json", directPkgs)
	if err != nil {
		t.Fatalf("absent optional dependency must not cause an error; got: %v", err)
	}
	if _, ok := findPkg(got, "present"); !ok {
		t.Errorf("installed dependency %q missing from resolved set: %#v", "present", got)
	}
}

// assertBuildOrLockMessage asserts the error guides the user to either build the
// app or generate a lock file — the contract this feature exists to enforce.
func assertBuildOrLockMessage(t *testing.T, err error) {
	t.Helper()
	msg := err.Error()
	for _, want := range []string{"no lockfile", "build the app", "generate a lock file"} {
		if !strings.Contains(msg, want) {
			t.Errorf("exit message missing %q; got: %v", want, msg)
		}
	}
}

func assertPkg(t *testing.T, pkgs []ScopedPackage, name, version, versionSpec string, direct bool) {
	t.Helper()
	p, ok := findPkg(pkgs, name)
	if !ok {
		t.Fatalf("package %q not found in %#v", name, pkgs)
	}
	if p.Version != version {
		t.Fatalf("%s version = %q, want %q", name, p.Version, version)
	}
	if p.VersionSpec != versionSpec {
		t.Fatalf("%s versionSpec = %q, want %q", name, p.VersionSpec, versionSpec)
	}
	if p.IsDirect != direct {
		t.Fatalf("%s IsDirect = %v, want %v", name, p.IsDirect, direct)
	}
}

func assertProvenance(t *testing.T, pkgs []ScopedPackage, name, sourceType, installedPath string) {
	t.Helper()
	p, ok := findPkg(pkgs, name)
	if !ok {
		t.Fatalf("package %q not found in %#v", name, pkgs)
	}
	if p.SourceType != sourceType {
		t.Errorf("%s SourceType = %q, want %q", name, p.SourceType, sourceType)
	}
	if p.InstalledPath != installedPath {
		t.Errorf("%s InstalledPath = %q, want %q", name, p.InstalledPath, installedPath)
	}
}

func writeNpmPackage(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
