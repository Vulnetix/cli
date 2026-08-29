package vex

import (
	"os"
	"path/filepath"
	"testing"
)

func loadDoc(t *testing.T, name string) *Document {
	t.Helper()
	doc, err := Load(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("Load(%s): %v", name, err)
	}
	return doc
}

func statementFor(doc *Document, vulnID string) *Statement {
	for i := range doc.Statements {
		if doc.Statements[i].VulnID == vulnID {
			return &doc.Statements[i]
		}
	}
	return nil
}

func TestDetectFormats(t *testing.T) {
	tests := map[string]Format{
		"vendor.openvex.json": FormatOpenVEX,
		"vendor.csaf.json":    FormatCSAF,
		"vendor.cdx-vex.json": FormatCycloneDX,
	}
	for name, want := range tests {
		data, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		if got := Detect(data); got != want {
			t.Errorf("Detect(%s) = %q, want %q", name, got, want)
		}
	}
	if got := Detect([]byte(`{"hello":"world"}`)); got != FormatUnknown {
		t.Errorf("Detect(non-VEX) = %q, want unknown", got)
	}
}

func TestParseOpenVEX(t *testing.T) {
	doc := loadDoc(t, "vendor.openvex.json")
	if doc.Author != "Acme Security" {
		t.Errorf("Author = %q", doc.Author)
	}
	if len(doc.Statements) != 3 {
		t.Fatalf("statements = %d, want 3", len(doc.Statements))
	}

	st := statementFor(doc, "CVE-2020-8203")
	if st == nil {
		t.Fatal("CVE-2020-8203 statement missing")
	}
	if st.Status != StatusNotAffected {
		t.Errorf("status = %q", st.Status)
	}
	if st.Justification != "vulnerable_code_not_in_execute_path" {
		t.Errorf("justification = %q", st.Justification)
	}
	if len(st.Products) != 1 || st.Products[0].Purl != "pkg:npm/lodash@4.17.20" {
		t.Errorf("products = %+v", st.Products)
	}
	if st.Source.Author != "Acme Security" {
		t.Errorf("source author = %q — a suppressed finding must be traceable", st.Source.Author)
	}
}

// TestVulnIDNormalisation is the bug that makes VEX silently do nothing: real
// documents carry the identifier as a URL, and comparing that against a scan's
// bare id fails on every one with no error.
func TestVulnIDNormalisation(t *testing.T) {
	doc := loadDoc(t, "vendor.openvex.json")
	if statementFor(doc, "CVE-2024-9999") == nil {
		t.Fatal("an NVD URL was not reduced to its bare CVE id")
	}

	tests := map[string]string{
		"https://nvd.nist.gov/vuln/detail/CVE-2021-44228": "CVE-2021-44228",
		"https://pkg.go.dev/vuln/GO-2023-1234":            "GO-2023-1234",
		"https://github.com/advisories/GHSA-aaaa-bbbb-cc": "GHSA-aaaa-bbbb-cc",
		"CVE-2021-44228":                "CVE-2021-44228",
		"  CVE-2021-44228  ":            "CVE-2021-44228",
		"https://example.com/v?q=CVE-1": "v",
		"":                              "",
	}
	for in, want := range tests {
		if got := normalizeVulnID(in); got != want {
			t.Errorf("normalizeVulnID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseCSAFVEX(t *testing.T) {
	doc := loadDoc(t, "vendor.csaf.json")
	if doc.Author != "Acme PSIRT" {
		t.Errorf("Author = %q", doc.Author)
	}
	st := statementFor(doc, "CVE-2026-1234")
	if st == nil {
		t.Fatal("CVE-2026-1234 statement missing")
	}
	if st.Status != StatusNotAffected {
		t.Errorf("status = %q, want not_affected", st.Status)
	}
	// CSAF scatters the justification into a flag and the prose into a threat,
	// both keyed by an opaque product id. Failing to reassemble them leaves a
	// not_affected with no argument behind it, which is unusable.
	if st.Justification != "component_not_present" {
		t.Errorf("justification = %q", st.Justification)
	}
	if st.ImpactStatement == "" {
		t.Error("impact statement was not carried across from the threat block")
	}
	// The purl lives in a nested product-tree branch, not beside the status.
	if len(st.Products) != 1 || st.Products[0].Purl != "pkg:npm/chalk@5.3.0" {
		t.Errorf("products = %+v — the product tree was not flattened", st.Products)
	}
}

func TestParseCDXVEX(t *testing.T) {
	doc := loadDoc(t, "vendor.cdx-vex.json")

	// A vulnerability entry with no analysis block is a finding, not an
	// assertion. Reading it as VEX would turn every SBOM into statements
	// asserting nothing.
	if len(doc.Statements) != 1 {
		t.Fatalf("statements = %d, want 1 (the entry without analysis is not a statement)", len(doc.Statements))
	}
	st := doc.Statements[0]
	if st.VulnID != "CVE-2020-28500" {
		t.Errorf("vulnId = %q", st.VulnID)
	}
	if st.Status != StatusNotAffected {
		t.Errorf("false_positive mapped to %q, want not_affected", st.Status)
	}
	if len(st.Products) != 1 || st.Products[0].Purl != "pkg:npm/lodash@4.17.20" {
		t.Errorf("products = %+v — the bom-ref was not resolved to a purl", st.Products)
	}
	if st.ImpactStatement == "" {
		t.Error("analysis.detail was not carried across")
	}
}

func TestLoadAllSkipsNonVEX(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, "vendor.openvex.json", filepath.Join(dir, "vendor.openvex.json"))
	// The usual invocation points at .vulnetix/, which also holds SBOMs and
	// SARIF. Refusing to run because a sibling file is not VEX would be
	// obstructive, so non-VEX is skipped, not fatal.
	if err := os.WriteFile(filepath.Join(dir, "sbom.cdx.json"),
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.json"), []byte(`{"a":1}`), 0o644); err != nil {
		t.Fatal(err)
	}

	docs, skipped, err := LoadAll([]string{dir})
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	// The SBOM has bomFormat CycloneDX so it is detected as CycloneDX VEX and
	// parsed; it simply yields no statements. notes.json is not VEX at all.
	if len(skipped) != 1 {
		t.Errorf("skipped = %v, want just the non-VEX file", skipped)
	}
	total := 0
	for _, d := range docs {
		total += len(d.Statements)
	}
	if total != 3 {
		t.Errorf("statements = %d, want the 3 from the OpenVEX document", total)
	}
}

func TestValidate(t *testing.T) {
	doc := loadDoc(t, "vendor.openvex.json")
	if problems := doc.Validate(); Fatal(problems) {
		t.Errorf("valid document reported fatal problems: %+v", problems)
	}

	// not_affected with no justification and no impact statement is invalid per
	// OpenVEX: the argument is the whole point of the status.
	bad, err := LoadBytes([]byte(`{
	  "@context":"https://openvex.dev/ns/v0.2.0","@id":"x","author":"a","version":1,
	  "statements":[{"vulnerability":{"name":"CVE-1"},"status":"not_affected"}]
	}`), "")
	if err != nil {
		t.Fatal(err)
	}
	problems := bad.Validate()
	if !Fatal(problems) {
		t.Errorf("unjustified not_affected was accepted: %+v", problems)
	}

	unknown, err := LoadBytes([]byte(`{
	  "@context":"https://openvex.dev/ns/v0.2.0","@id":"x","author":"a","version":1,
	  "statements":[{"vulnerability":{"name":"CVE-1"},"status":"probably_fine"}]
	}`), "")
	if err != nil {
		t.Fatal(err)
	}
	if !Fatal(unknown.Validate()) {
		t.Error("a status outside the vocabulary was accepted")
	}
}

func copyFixture(t *testing.T, name, dest string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
