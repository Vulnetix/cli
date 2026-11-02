package artifacts

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRecordAndRead(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "out", "manifest.jsonl")
	t.Setenv(EnvVar, manifest)
	FlagPath = ""

	a := filepath.Join(dir, "a.sarif")
	b := filepath.Join(dir, "b.cdx.json")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	SetCommand("sast")
	Record(a, "sarif")
	Record(b, KindFor(b))
	Record(a, "sarif") // written twice: one entry
	Record(filepath.Join(dir, "missing"), "sarif")

	got, err := Read(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Path != a || got[0].Kind != "sarif" || got[1].Kind != "cyclonedx" || got[0].Command != "sast" || got[0].SHA256 == "" {
		t.Fatalf("entries %+v", got)
	}

	// A file removed after it was recorded is not listed.
	if err := os.Remove(b); err != nil {
		t.Fatal(err)
	}
	if got, _ := Read(manifest); len(got) != 1 {
		t.Fatalf("after removal %+v", got)
	}
}

func TestRecordWithoutManifestDoesNothing(t *testing.T) {
	t.Setenv(EnvVar, "")
	FlagPath = ""
	p := filepath.Join(t.TempDir(), "a.sarif")
	_ = os.WriteFile(p, []byte("x"), 0o644)
	Record(p, "sarif") // must not panic or write anywhere
}

func TestFlagWinsOverEnv(t *testing.T) {
	t.Setenv(EnvVar, "/env")
	FlagPath = "/flag"
	defer func() { FlagPath = "" }()
	if Path() != "/flag" {
		t.Fatal(Path())
	}
}
