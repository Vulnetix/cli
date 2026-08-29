package vex

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMergeNewestWins(t *testing.T) {
	march := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	june := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	docs := []*Document{
		{Statements: []Statement{{
			VulnID: "CVE-1", Status: StatusUnderInvestigation,
			Products: []Product{{Purl: "pkg:npm/foo@1.0.0"}}, Timestamp: march,
		}}},
		{Statements: []Statement{{
			VulnID: "CVE-1", Status: StatusNotAffected, Justification: "component_not_present",
			Products: []Product{{Purl: "pkg:npm/foo@1.0.0"}}, Timestamp: june,
		}}},
	}

	merged := Merge(docs)
	if len(merged) != 1 {
		t.Fatalf("merged = %d statements, want 1 — the June statement supersedes March", len(merged))
	}
	if merged[0].Status != StatusNotAffected {
		t.Errorf("status = %q, want the newer not_affected", merged[0].Status)
	}
}

// TestMergeKeepsDistinctProducts pins that superseding is per-product: a newer
// statement about one package must not swallow an older one about another.
func TestMergeKeepsDistinctProducts(t *testing.T) {
	docs := []*Document{
		{Statements: []Statement{
			{VulnID: "CVE-1", Status: StatusNotAffected, Justification: "component_not_present",
				Products: []Product{{Purl: "pkg:npm/foo@1.0.0"}}},
			{VulnID: "CVE-1", Status: StatusAffected, ActionStatement: "upgrade",
				Products: []Product{{Purl: "pkg:npm/bar@2.0.0"}}},
		}},
	}
	merged := Merge(docs)
	if len(merged) != 2 {
		t.Fatalf("merged = %d, want 2 — different products are different assertions", len(merged))
	}
}

func TestMergeAcrossFormats(t *testing.T) {
	docs := []*Document{
		loadDoc(t, "vendor.openvex.json"),
		loadDoc(t, "vendor.csaf.json"),
		loadDoc(t, "vendor.cdx-vex.json"),
	}
	merged := Merge(docs)
	// 3 OpenVEX + 1 CSAF + 1 CycloneDX (the entry without an analysis block is
	// not a statement).
	if len(merged) != 5 {
		t.Fatalf("merged = %d, want 5", len(merged))
	}
}

// TestWriteOpenVEXRoundTrips pins that a merged document can be read back — a
// merge that produced something this CLI cannot parse would be useless.
func TestWriteOpenVEXRoundTrips(t *testing.T) {
	docs := []*Document{loadDoc(t, "vendor.openvex.json"), loadDoc(t, "vendor.csaf.json")}
	merged := Merge(docs)

	data, err := WriteOpenVEX(merged, WriteOptions{
		Author: "Vulnetix", Now: time.Date(2026, 8, 4, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if Detect(data) != FormatOpenVEX {
		t.Fatal("written document is not detected as OpenVEX")
	}

	back, err := LoadBytes(data, "merged.openvex.json")
	if err != nil {
		t.Fatalf("re-reading the merged document: %v", err)
	}
	if len(back.Statements) != len(merged) {
		t.Errorf("round trip changed the statement count: %d → %d", len(merged), len(back.Statements))
	}

	// A merge must not invent anything the sources did not say.
	csaf := statementFor(back, "CVE-2026-1234")
	if csaf == nil {
		t.Fatal("the CSAF statement did not survive the merge")
	}
	if csaf.Justification != "component_not_present" {
		t.Errorf("justification = %q, want it carried through unchanged", csaf.Justification)
	}
	if csaf.Status != StatusNotAffected {
		t.Errorf("status = %q", csaf.Status)
	}
}

func TestWriteOpenVEXShape(t *testing.T) {
	data, err := WriteOpenVEX([]Statement{{
		VulnID: "CVE-1", Status: StatusNotAffected, Justification: "component_not_present",
		Products: []Product{{Purl: "pkg:npm/foo@1.0.0", Versions: []string{"1.0.0"}}},
	}}, WriteOptions{Now: time.Date(2026, 8, 4, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}

	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["@context"] != "https://openvex.dev/ns/v0.2.0" {
		t.Errorf("@context = %v", doc["@context"])
	}
	if doc["author"] != "Vulnetix" {
		t.Errorf("author = %v, want the default", doc["author"])
	}
	stmts, _ := doc["statements"].([]any)
	if len(stmts) != 1 {
		t.Fatalf("statements = %d", len(stmts))
	}
	// A statement with no timestamp of its own must still carry one, or a later
	// merge has nothing to order it by.
	s, _ := stmts[0].(map[string]any)
	if s["timestamp"] == "" || s["timestamp"] == nil {
		t.Error("statement has no timestamp; a later merge could not order it")
	}
}
