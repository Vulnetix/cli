package scan

import (
	"os"
	"path/filepath"
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
