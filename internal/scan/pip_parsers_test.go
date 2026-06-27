package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func loadPyFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "python-ssvc", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

// TestParseRequirementsTxtScoped_HashesAndVia verifies the rewritten parser
// captures every --hash (across `\`-continuation lines) and derives direct vs
// transitive from the `# via` block, on real `uv pip compile --generate-hashes`
// output shape.
func TestParseRequirementsTxtScoped_HashesAndVia(t *testing.T) {
	pkgs, err := parseRequirementsTxtScoped(loadPyFixture(t, "requirements.txt"), "requirements.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("want 3 packages, got %d: %+v", len(pkgs), pkgs)
	}

	attrs, ok := findPkg(pkgs, "attrs")
	if !ok {
		t.Fatal("attrs not found")
	}
	if attrs.Version != "25.3.0" {
		t.Errorf("attrs version = %q, want 25.3.0", attrs.Version)
	}
	if len(attrs.Checksums) != 2 {
		t.Errorf("attrs checksums = %d, want 2", len(attrs.Checksums))
	}
	for _, c := range attrs.Checksums {
		if c.Alg != "SHA-256" {
			t.Errorf("attrs checksum alg = %q, want SHA-256", c.Alg)
		}
	}
	if !attrs.IsDirect {
		t.Error("attrs has `# via -r requirements.in` and must be direct")
	}

	// rpds-py's via block lists only a parent package (referencing), so it is
	// transitive, not direct.
	rpds, ok := findPkg(pkgs, "rpds-py")
	if !ok {
		t.Fatal("rpds-py not found")
	}
	if rpds.IsDirect {
		t.Error("rpds-py is `# via referencing` only and must be transitive")
	}
	if len(rpds.Checksums) != 2 {
		t.Errorf("rpds-py checksums = %d, want 2", len(rpds.Checksums))
	}
}

func TestParsePylockTOMLScoped(t *testing.T) {
	pkgs, err := parsePylockTOMLScoped(loadPyFixture(t, "pylock.toml"), "pylock.toml")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("want 2 packages, got %d", len(pkgs))
	}
	attrs, ok := findPkg(pkgs, "attrs")
	if !ok {
		t.Fatal("attrs not found")
	}
	if attrs.Version != "25.3.0" {
		t.Errorf("attrs version = %q", attrs.Version)
	}
	// sdist + one wheel → 2 hashes.
	if len(attrs.Checksums) != 2 {
		t.Errorf("attrs checksums = %d, want 2 (sdist + wheel)", len(attrs.Checksums))
	}
}

func TestParseUVLockScoped_HashesAndEdges(t *testing.T) {
	pkgs, err := parseUVLockScoped(loadPyFixture(t, "uv.lock"), "uv.lock")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 4 {
		t.Fatalf("want 4 packages, got %d: %+v", len(pkgs), pkgs)
	}
	cc, ok := findPkg(pkgs, "cachecontrol")
	if !ok {
		t.Fatal("cachecontrol not found")
	}
	if cc.Version != "0.14.1" {
		t.Errorf("cachecontrol version = %q", cc.Version)
	}
	if len(cc.Checksums) != 2 {
		t.Errorf("cachecontrol checksums = %d, want 2 (inline sdist + wheel)", len(cc.Checksums))
	}

	// Dependency tree (deps + optional-deps) flows into the graph edges, keyed by
	// the normalised name.
	g := &DepGraph{}
	g.PopulatePypiLockEdges(filepath.Join("testdata", "python-ssvc"))
	want := map[string]bool{"msgpack": true, "requests": true, "filelock": true}
	for _, c := range g.Edges[normPypi("cachecontrol")] {
		delete(want, c)
	}
	if len(want) != 0 {
		t.Errorf("cachecontrol edges missing %v; got %v", want, g.Edges[normPypi("cachecontrol")])
	}
	// requirements.txt `# via` inversion contributes referencing → rpds-py.
	if got := g.Edges[normPypi("referencing")]; len(got) == 0 {
		t.Errorf("expected referencing → rpds_py edge from `# via`, got none")
	}
}
