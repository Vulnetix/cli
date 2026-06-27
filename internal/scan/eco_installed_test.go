package scan

import (
	"path/filepath"
	"strings"
	"testing"
)

// isolateHome points HOME / package-manager cache envs at empty temp dirs so a
// resolver test never reads the developer's real global caches.
func isolateHome(t *testing.T) {
	t.Helper()
	empty := t.TempDir()
	t.Setenv("HOME", empty)
	t.Setenv("CARGO_HOME", filepath.Join(empty, "nocargo"))
	t.Setenv("GEM_HOME", "")
	t.Setenv("PUB_CACHE", filepath.Join(empty, "nopub"))
	t.Setenv("NUGET_PACKAGES", filepath.Join(empty, "nonuget"))
}

func assertProv(t *testing.T, pkgs []ScopedPackage, name, sourceType string, wantDirect bool) {
	t.Helper()
	p, ok := findPkg(pkgs, name)
	if !ok {
		t.Fatalf("%s not in resolved set %v", name, names(pkgs))
	}
	if p.SourceType != sourceType {
		t.Errorf("%s SourceType = %q, want %q", name, p.SourceType, sourceType)
	}
	if p.IsDirect != wantDirect {
		t.Errorf("%s IsDirect = %v, want %v", name, p.IsDirect, wantDirect)
	}
	if sourceType == SourceTypeInstalled && p.InstalledPath == "" {
		t.Errorf("%s installed transitive has empty InstalledPath", name)
	}
	if sourceType == SourceTypeManifest && p.InstalledPath != "" {
		t.Errorf("%s manifest dep has non-empty InstalledPath %q", name, p.InstalledPath)
	}
}

func names(pkgs []ScopedPackage) []string {
	var out []string
	for _, p := range pkgs {
		out = append(out, p.Name)
	}
	return out
}

// ── cargo (project vendor → full) ─────────────────────────────────────────────

func TestResolveCargo_VendorProvenance(t *testing.T) {
	isolateHome(t)
	root := t.TempDir()
	writePyTestFile(t, filepath.Join(root, "Cargo.toml"), "[package]\nname=\"app\"\n")
	writePyTestFile(t, filepath.Join(root, "vendor", "serde", "Cargo.toml"), "[package]\nname = \"serde\"\nversion = \"1.0.210\"\n")
	writePyTestFile(t, filepath.Join(root, "vendor", "serde_derive", "Cargo.toml"), "[package]\nname = \"serde_derive\"\nversion = \"1.0.210\"\n")

	declared := []ScopedPackage{{Name: "serde", Ecosystem: "cargo", VersionSpec: "1", IsDirect: true}}
	got, err := ResolveCargoFromInstalled(filepath.Join(root, "Cargo.toml"), "Cargo.toml", declared, true)
	if err != nil {
		t.Fatal(err)
	}
	assertProv(t, got, "serde", SourceTypeManifest, true)
	assertProv(t, got, "serde_derive", SourceTypeInstalled, false) // vendored transitive
}

func TestResolveCargo_NoLockNoInstallErrors(t *testing.T) {
	isolateHome(t)
	root := t.TempDir()
	writePyTestFile(t, filepath.Join(root, "Cargo.toml"), "[package]\nname=\"app\"\n")
	_, err := ResolveCargoFromInstalled(filepath.Join(root, "Cargo.toml"), "Cargo.toml",
		[]ScopedPackage{{Name: "serde"}}, true)
	if err == nil {
		t.Fatal("expected build-or-lock error with no Cargo.lock and no vendor")
	}
	if !strings.Contains(err.Error(), "Cargo.lock") {
		t.Errorf("error should mention Cargo.lock: %v", err)
	}
}

// ── rubygems (project bundle → full) ──────────────────────────────────────────

func TestResolveGems_BundleProvenance(t *testing.T) {
	isolateHome(t)
	root := t.TempDir()
	writePyTestFile(t, filepath.Join(root, "Gemfile"), "source 'https://rubygems.org'\n")
	gemsDir := filepath.Join(root, "vendor", "bundle", "ruby", "3.3.0", "gems")
	writePyTestFile(t, filepath.Join(gemsDir, "rails-7.1.0", "x"), "")
	writePyTestFile(t, filepath.Join(gemsDir, "activesupport-7.1.0", "x"), "")

	declared := []ScopedPackage{{Name: "rails", Ecosystem: "rubygems", VersionSpec: "~> 7.1", IsDirect: true}}
	got, err := ResolveGemsFromInstalled(filepath.Join(root, "Gemfile"), "Gemfile", declared, true)
	if err != nil {
		t.Fatal(err)
	}
	assertProv(t, got, "rails", SourceTypeManifest, true)
	assertProv(t, got, "activesupport", SourceTypeInstalled, false)
}

// ── composer (project vendor → full) ──────────────────────────────────────────

func TestResolveComposer_VendorProvenance(t *testing.T) {
	isolateHome(t)
	root := t.TempDir()
	writePyTestFile(t, filepath.Join(root, "composer.json"), "{}")
	writePyTestFile(t, filepath.Join(root, "vendor", "monolog", "monolog", "composer.json"), `{"name":"monolog/monolog","version":"3.7.0"}`)
	writePyTestFile(t, filepath.Join(root, "vendor", "psr", "log", "composer.json"), `{"name":"psr/log","version":"3.0.0"}`)

	declared := []ScopedPackage{{Name: "monolog/monolog", Ecosystem: "composer", VersionSpec: "^3.0", IsDirect: true}}
	got, err := ResolveComposerFromInstalled(filepath.Join(root, "composer.json"), "composer.json", declared, true)
	if err != nil {
		t.Fatal(err)
	}
	assertProv(t, got, "monolog/monolog", SourceTypeManifest, true)
	assertProv(t, got, "psr/log", SourceTypeInstalled, false)
}

// ── pub (project .dart_tool → full) ───────────────────────────────────────────

func TestResolvePub_DartToolProvenance(t *testing.T) {
	isolateHome(t)
	root := t.TempDir()
	writePyTestFile(t, filepath.Join(root, "pubspec.yaml"), "name: app\n")
	cfg := `{"configVersion":2,"packages":[
	  {"name":"http","rootUri":"file:///cache/hosted/pub.dev/http-1.2.2"},
	  {"name":"path","rootUri":"file:///cache/hosted/pub.dev/path-1.9.0"},
	  {"name":"app","rootUri":"../"}
	]}`
	writePyTestFile(t, filepath.Join(root, ".dart_tool", "package_config.json"), cfg)

	declared := []ScopedPackage{{Name: "http", Ecosystem: "pub", VersionSpec: "^1.2.0", IsDirect: true}}
	got, err := ResolvePubFromInstalled(filepath.Join(root, "pubspec.yaml"), "pubspec.yaml", declared, true)
	if err != nil {
		t.Fatal(err)
	}
	assertProv(t, got, "http", SourceTypeManifest, true)
	assertProv(t, got, "path", SourceTypeInstalled, false)
	if h, _ := findPkg(got, "http"); h.Version != "1.2.2" {
		t.Errorf("http version = %q, want 1.2.2", h.Version)
	}
}

// ── hex (project deps → full) ─────────────────────────────────────────────────

func TestResolveHex_DepsProvenance(t *testing.T) {
	isolateHome(t)
	root := t.TempDir()
	writePyTestFile(t, filepath.Join(root, "mix.exs"), "defmodule App.MixProject do end\n")
	writePyTestFile(t, filepath.Join(root, "deps", "phoenix", "hex_metadata.config"), `{<<"app">>,<<"phoenix">>}.`+"\n"+`{<<"version">>,<<"1.7.14">>}.`+"\n")
	writePyTestFile(t, filepath.Join(root, "deps", "plug", "hex_metadata.config"), `{<<"version">>,<<"1.16.1">>}.`+"\n")

	declared := []ScopedPackage{{Name: "phoenix", Ecosystem: "hex", VersionSpec: "~> 1.7", IsDirect: true}}
	got, err := ResolveHexFromInstalled(filepath.Join(root, "mix.exs"), "mix.exs", declared, true)
	if err != nil {
		t.Fatal(err)
	}
	assertProv(t, got, "phoenix", SourceTypeManifest, true)
	assertProv(t, got, "plug", SourceTypeInstalled, false)
}

// ── nuget (global cache → declared-only, no transitive enumeration) ───────────

func TestResolveNuget_GlobalDeclaredOnly(t *testing.T) {
	isolateHome(t)
	home := t.TempDir()
	t.Setenv("NUGET_PACKAGES", filepath.Join(home, ".nuget", "packages"))
	// Two packages cached globally; only one is declared.
	writePyTestFile(t, filepath.Join(home, ".nuget", "packages", "newtonsoft.json", "13.0.3", "x"), "")
	writePyTestFile(t, filepath.Join(home, ".nuget", "packages", "unrelated.pkg", "9.9.9", "x"), "")
	root := t.TempDir()
	writePyTestFile(t, filepath.Join(root, "App.csproj"), "<Project></Project>")

	declared := []ScopedPackage{{Name: "Newtonsoft.Json", Ecosystem: "nuget", Version: "13.0.3"}}
	got, err := ResolveNugetFromInstalled(filepath.Join(root, "App.csproj"), "App.csproj", declared, true)
	if err != nil {
		t.Fatal(err)
	}
	assertProv(t, got, "Newtonsoft.Json", SourceTypeManifest, true)
	// Global caches must NOT be enumerated as transitives.
	if _, ok := findPkg(got, "unrelated.pkg"); ok {
		t.Error("global cache package leaked into the resolved set (must be declared-only)")
	}
}

// ── go (gate is a no-op; never errors even without go.sum) ─────────────────────

func TestGoGate_NeverErrors(t *testing.T) {
	isolateHome(t)
	root := t.TempDir()
	writePyTestFile(t, filepath.Join(root, "go.mod"), "module x\n\nrequire github.com/foo/bar v1.2.3\n")
	declared := []ScopedPackage{{Name: "github.com/foo/bar", Version: "v1.2.3", Ecosystem: "golang"}}
	got, drop, err := ApplyBuildOrLockGate("golang", "go.mod", filepath.Join(root, "go.mod"), "go.mod", true, declared)
	if err != nil || drop {
		t.Fatalf("go gate must be a no-op: err=%v drop=%v", err, drop)
	}
	if len(got) != 1 {
		t.Errorf("go gate altered packages: %v", names(got))
	}
}

// ── end-to-end gate dispatch via the registry ─────────────────────────────────

func TestApplyGate_CargoFatalWhenUnresolvable(t *testing.T) {
	isolateHome(t)
	root := t.TempDir()
	writePyTestFile(t, filepath.Join(root, "Cargo.toml"), "[package]\nname=\"app\"\n")
	_, drop, err := ApplyBuildOrLockGate("cargo", "Cargo.toml", filepath.Join(root, "Cargo.toml"), "Cargo.toml",
		true, []ScopedPackage{{Name: "serde"}})
	if err == nil || drop {
		t.Fatalf("confident cargo with no lock/install should be a fatal error: err=%v drop=%v", err, drop)
	}
}

func TestApplyGate_LockPresentSkips(t *testing.T) {
	isolateHome(t)
	root := t.TempDir()
	writePyTestFile(t, filepath.Join(root, "Cargo.toml"), "[package]\nname=\"app\"\n")
	writePyTestFile(t, filepath.Join(root, "Cargo.lock"), "version = 3\n")
	declared := []ScopedPackage{{Name: "serde"}}
	got, drop, err := ApplyBuildOrLockGate("cargo", "Cargo.toml", filepath.Join(root, "Cargo.toml"), "Cargo.toml", true, declared)
	if err != nil || drop {
		t.Fatalf("Cargo.lock present should skip the gate: err=%v drop=%v", err, drop)
	}
	if len(got) != 1 {
		t.Errorf("gate altered packages when a lock was present: %v", names(got))
	}
}
