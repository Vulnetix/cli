package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vulnetix/cli/v3/internal/scan"
)

func TestLooksLikeAdvisoryID(t *testing.T) {
	for q, want := range map[string]bool{
		"cve-2024-1234": true, "ghsa-xxxx-9xxx-xxxx": true, "pysec-2024-38": true, "go-2024-1234": true,
		"requests": false, "log4j-core": false, "requests@2.31.0": false, "src/app.py": false,
		"vnx-": false, "-1": false, "vnx-py-004": false,
	} {
		if got := looksLikeAdvisoryID(q); got != want {
			t.Errorf("looksLikeAdvisoryID(%q) = %v, want %v", q, got, want)
		}
	}
}

// --explain asks the VDB about the packages it names and nothing else.
func TestExplainPackagesNarrowsTheQuery(t *testing.T) {
	pkgs := []scan.ScopedPackage{
		{Name: "requests", Version: "2.31.0", Ecosystem: "pypi"},
		{Name: "urllib3", Version: "1.26.0", Ecosystem: "pypi"},
		{Name: "requests", Version: "2.20.0", Ecosystem: "pypi"},
	}
	dir := t.TempDir()

	got, matched, resolved := explainPackages(pkgs, "Requests", dir)
	if !matched || !resolved || len(got) != 2 {
		t.Errorf("by name: got %d packages (matched=%v resolved=%v), want both requests", len(got), matched, resolved)
	}
	got, _, _ = explainPackages(pkgs, "requests@2.20.0", dir)
	if len(got) != 1 || got[0].Version != "2.20.0" {
		t.Errorf("by name@version: got %+v", got)
	}
	// A rule id or a path names no package: there is nothing to ask the VDB.
	for _, q := range []string{"VNX-PY-004", "src/app.py"} {
		if _, matched, _ := explainPackages(pkgs, q, dir); matched {
			t.Errorf("%q should name no package", q)
		}
	}

	// An advisory id resolves through the last scan's SBOM, aliases included.
	sbom := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
	  {"type":"library","bom-ref":"u","name":"urllib3","version":"1.26.0"}],
	  "vulnerabilities":[{"id":"CVE-2024-37891","references":[{"id":"GHSA-34jh-p97f-mpxf"}],"affects":[{"ref":"u"}]}]}`
	if err := os.MkdirAll(filepath.Join(dir, ".vulnetix"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".vulnetix", "sbom.cdx.json"), []byte(sbom), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"CVE-2024-37891", "ghsa-34jh-p97f-mpxf"} {
		got, matched, resolved := explainPackages(pkgs, q, dir)
		if !matched || !resolved || len(got) != 1 || got[0].Name != "urllib3" {
			t.Errorf("%s: got %+v (matched=%v resolved=%v), want urllib3", q, got, matched, resolved)
		}
	}
}
