package reachability

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMatchAffectedSymbols_GrepsSourceForRoutineHit proves the end-to-end
// grep-style symbol fallback pipeline: given a project root containing a Go
// source file that references a known-vulnerable routine name, the matcher
// returns a hit keyed by the supplied CVE id. This is the deterministic
// evidence that proves the cli.sca → SynthesiseFromCDX → MatchAffectedSymbols
// chain fires correctly even when the live DB has sparse symbol data for the
// CVEs we happened to test.
func TestMatchAffectedSymbols_GrepsSourceForRoutineHit(t *testing.T) {
	dir := t.TempDir()
	src := `package vuln

// CVE-9999-XXXX touches BeanDeserializer in this hypothetical file.
func use() string {
	x := BeanDeserializer{}
	_ = x
	return "ok"
}

type BeanDeserializer struct{}
`
	if err := os.WriteFile(filepath.Join(dir, "vuln.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	res, err := MatchAffectedSymbols(context.Background(), SymbolMatchRequest{
		ProjectRoot: dir,
		Inputs: []CveSymbols{
			{
				CveID:    "CVE-2019-14379",
				Routines: []string{"BeanDeserializer", "ObjectMapper"}, // jackson-databind-style
			},
		},
	})
	if err != nil {
		t.Fatalf("matcher returned error: %v", err)
	}
	if res == nil {
		t.Fatal("matcher returned nil result")
	}
	hits, ok := res.HitsByCVE["CVE-2019-14379"]
	if !ok || len(hits) == 0 {
		t.Fatalf("expected CVE-2019-14379 to register a hit; got %+v", res.HitsByCVE)
	}
	got := hits[0]
	if got.Symbol != "BeanDeserializer" {
		t.Errorf("expected symbol BeanDeserializer; got %q", got.Symbol)
	}
	if got.Kind != "routine" {
		t.Errorf("expected kind=routine; got %q", got.Kind)
	}
	if !strings.HasSuffix(got.File, "vuln.go") {
		t.Errorf("expected hit in vuln.go; got %q", got.File)
	}
}

// TestMatchAffectedSymbols_RejectsLowQualitySymbols proves that the quality
// threshold drops short / lowercase routine names so common verbs like
// "parse" or "open" don't false-positive every project on Earth.
func TestMatchAffectedSymbols_RejectsLowQualitySymbols(t *testing.T) {
	dir := t.TempDir()
	src := `package x
func parse() {}
func open() {}
func main() { parse(); open() }
`
	if err := os.WriteFile(filepath.Join(dir, "m.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	res, err := MatchAffectedSymbols(context.Background(), SymbolMatchRequest{
		ProjectRoot: dir,
		Inputs: []CveSymbols{{
			CveID:    "CVE-X",
			Routines: []string{"parse", "open", "read"}, // all rejected by isQualitySymbol
		}},
	})
	if err != nil {
		t.Fatalf("matcher returned error: %v", err)
	}
	if got := len(res.HitsByCVE); got != 0 {
		t.Errorf("low-quality symbols should produce zero hits; got %d", got)
	}
}

// TestMatchAffectedSymbols_FileNameHit covers the affectedFiles path, where
// the symbol is a literal filename to look for in the walked tree.
func TestMatchAffectedSymbols_FileNameHit(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "src", "lib"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "src", "lib", "deserialize.c"), []byte("// vuln\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	res, err := MatchAffectedSymbols(context.Background(), SymbolMatchRequest{
		ProjectRoot: dir,
		Inputs: []CveSymbols{{
			CveID: "CVE-Y",
			Files: []string{"deserialize.c"},
		}},
	})
	if err != nil {
		t.Fatalf("matcher returned error: %v", err)
	}
	if len(res.HitsByCVE["CVE-Y"]) == 0 {
		t.Fatalf("expected file-name hit for deserialize.c; got %+v", res.HitsByCVE)
	}
	if res.HitsByCVE["CVE-Y"][0].Kind != "file" {
		t.Errorf("expected kind=file; got %q", res.HitsByCVE["CVE-Y"][0].Kind)
	}
}

// TestIsQualitySymbol covers the inline filter rule independently so future
// tuning has a single place to look.
func TestIsQualitySymbol(t *testing.T) {
	cases := map[string]bool{
		"":                 false,
		"x":                false,
		"open":             false, // too short, all lowercase
		"parse":            false,
		"foobar":           false, // length ok but no capital/dot/underscore
		"FooBar":           true,
		"foo.bar.baz":      true,
		"my_function_name": true,
		"BeanDeserializer": true,
	}
	for in, want := range cases {
		if got := isQualitySymbol(in); got != want {
			t.Errorf("isQualitySymbol(%q) = %v; want %v", in, got, want)
		}
	}
}
