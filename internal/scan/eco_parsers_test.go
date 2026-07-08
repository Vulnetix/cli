package scan

import (
	"github.com/Vulnetix/vdb-sca-match/parse"

	"os"
	"path/filepath"
	"testing"
)

func loadEcoFixture(t *testing.T, eco, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "eco", eco, name))
	if err != nil {
		t.Fatalf("read fixture %s/%s: %v", eco, name, err)
	}
	return data
}

func hashCount(pkgs []ScopedPackage, name string) int {
	if p, ok := findPkg(pkgs, name); ok {
		return len(p.Checksums)
	}
	return -1
}

// cargo: checksums already captured; this guards the new dependency-tree edges.
func TestParseCargoLock_Edges(t *testing.T) {
	pkgs, err := parse.ParseManifest(loadEcoFixture(t, "cargo", "Cargo.lock"), "Cargo.lock", "Cargo.lock")
	if err != nil {
		t.Fatal(err)
	}
	if hashCount(pkgs, "serde") != 1 {
		t.Errorf("serde checksums = %d, want 1", hashCount(pkgs, "serde"))
	}
	g := &DepGraph{}
	g.PopulateCargoLockEdges(filepath.Join("testdata", "eco", "cargo"))
	assertEdge(t, g, "cargo-lock-test", "serde")
	assertEdge(t, g, "serde", "serde_derive")
}

// gradle: guards the name/version split bug fix.
func TestParseGradleLockfile_NameVersionSplit(t *testing.T) {
	pkgs, err := parse.ParseManifest(loadEcoFixture(t, "gradle", "gradle.lockfile"), "gradle.lockfile", "gradle.lockfile")
	if err != nil {
		t.Fatal(err)
	}
	gson, ok := findPkg(pkgs, "com.google.code.gson:gson")
	if !ok {
		t.Fatalf("gson not found by group:artifact name; got %+v", pkgs)
	}
	if gson.Version != "2.11.0" {
		t.Errorf("gson version = %q, want 2.11.0", gson.Version)
	}
	// the "empty=" marker line must not produce a package
	if _, ok := findPkg(pkgs, "empty"); ok {
		t.Error("the empty= marker line was ingested as a package")
	}
}

// gemfile: guards the dep-line-leak bug fix + CHECKSUMS + edges.
func TestParseGemfileLock_NoDepLineLeak(t *testing.T) {
	pkgs, err := parse.ParseManifest(loadEcoFixture(t, "ruby", "Gemfile.lock"), "Gemfile.lock", "Gemfile.lock")
	if err != nil {
		t.Fatal(err)
	}
	// actionpack appears exactly once, at its real version (never as actionpack@"=").
	count, version := 0, ""
	for _, p := range pkgs {
		if p.Name == "actionpack" {
			count++
			version = p.Version
		}
		if p.Version == "=" || p.Version == "" {
			t.Errorf("garbage package from a dependency line: %+v", p)
		}
	}
	if count != 1 || version != "7.1.3.4" {
		t.Errorf("actionpack: count=%d version=%q, want 1 / 7.1.3.4", count, version)
	}
	// CHECKSUMS captured.
	if hashCount(pkgs, "actionpack") != 1 {
		t.Errorf("actionpack checksums = %d, want 1 (from CHECKSUMS)", hashCount(pkgs, "actionpack"))
	}
	// edges: actioncable → actionpack.
	g := &DepGraph{}
	g.PopulateGemfileLockEdges(filepath.Join("testdata", "eco", "ruby"))
	assertEdge(t, g, "actioncable", "actionpack")
}

// composer: guards dist.shasum capture + require edges.
func TestParseComposerLock_HashAndEdges(t *testing.T) {
	pkgs, err := parse.ParseManifest(loadEcoFixture(t, "composer", "composer.lock"), "composer.lock", "composer.lock")
	if err != nil {
		t.Fatal(err)
	}
	if hashCount(pkgs, "monolog/monolog") != 1 {
		t.Errorf("monolog checksums = %d, want 1 (dist.shasum)", hashCount(pkgs, "monolog/monolog"))
	}
	g := &DepGraph{}
	g.PopulateComposerLockEdges(filepath.Join("testdata", "eco", "composer"))
	assertEdge(t, g, "monolog/monolog", "psr/log")
	// platform require (php) must not become an edge.
	for _, c := range g.Edges["monolog/monolog"] {
		if c == "php" {
			t.Error("php platform requirement leaked into edges")
		}
	}
}

// nuget: guards the schema rewrite (was returning zero packages) + contentHash + edges.
func TestParseNugetLock_SchemaAndHash(t *testing.T) {
	pkgs, err := parse.ParseManifest(loadEcoFixture(t, "nuget", "packages.lock.json"), "packages.lock.json", "packages.lock.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) == 0 {
		t.Fatal("nuget parser returned zero packages (schema regression)")
	}
	nj, ok := findPkg(pkgs, "Newtonsoft.Json")
	if !ok || nj.Version != "13.0.3" || !nj.IsDirect {
		t.Errorf("Newtonsoft.Json = %+v, want 13.0.3 direct", nj)
	}
	if hashCount(pkgs, "Newtonsoft.Json") != 1 || nj.Checksums[0].Alg != "SHA-512" {
		t.Errorf("Newtonsoft.Json checksums = %+v, want one SHA-512", nj.Checksums)
	}
	ser, ok := findPkg(pkgs, "Serilog")
	if !ok || ser.IsDirect {
		t.Errorf("Serilog should be a transitive (non-direct): %+v", ser)
	}
	g := &DepGraph{}
	g.PopulateNugetLockEdges(filepath.Join("testdata", "eco", "nuget"))
	assertEdge(t, g, "Serilog.Sinks.File", "Serilog")
}

// hex: guards the realistic-format rewrite (inner + outer 64-hex) + deps edges.
func TestParseMixLock_HashesAndEdges(t *testing.T) {
	pkgs, err := parse.ParseManifest(loadEcoFixture(t, "hex", "mix.lock"), "mix.lock", "mix.lock")
	if err != nil {
		t.Fatal(err)
	}
	phx, ok := findPkg(pkgs, "phoenix")
	if !ok || phx.Version != "1.7.14" {
		t.Fatalf("phoenix = %+v, want 1.7.14", phx)
	}
	if len(phx.Checksums) != 2 {
		t.Errorf("phoenix checksums = %d, want 2 (inner + outer)", len(phx.Checksums))
	}
	g := &DepGraph{}
	g.PopulateMixLockEdges(filepath.Join("testdata", "eco", "hex"))
	assertEdge(t, g, "phoenix", "plug")
	assertEdge(t, g, "phoenix", "telemetry")
}

// pub: guards description.sha256 capture.
func TestParsePubspecLock_Sha256(t *testing.T) {
	pkgs, err := parse.ParseManifest(loadEcoFixture(t, "pub", "pubspec.lock"), "pubspec.lock", "pubspec.lock")
	if err != nil {
		t.Fatal(err)
	}
	if hashCount(pkgs, "http") != 1 {
		t.Errorf("http checksums = %d, want 1 (description.sha256)", hashCount(pkgs, "http"))
	}
	if p, ok := findPkg(pkgs, "http"); !ok || !p.IsDirect {
		t.Errorf("http should be direct: %+v", p)
	}
}

func assertEdge(t *testing.T, g *DepGraph, parent, child string) {
	t.Helper()
	for _, c := range g.Edges[parent] {
		if c == child {
			return
		}
	}
	t.Errorf("expected edge %q → %q; got %v", parent, child, g.Edges[parent])
}
