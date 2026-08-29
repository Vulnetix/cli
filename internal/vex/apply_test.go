package vex

import (
	"testing"

	"github.com/vulnetix/cli/v3/internal/cdx"
)

// testBOM is a small document whose entries the fixture statements reach.
func testBOM() *cdx.BOM {
	return &cdx.BOM{
		BOMFormat: "CycloneDX", SpecVersion: "1.6", Version: 1,
		Components: []cdx.Component{
			{Type: "library", BOMRef: "pkg:npm/lodash@4.17.20", Name: "lodash",
				Version: "4.17.20", Purl: "pkg:npm/lodash@4.17.20"},
			{Type: "library", BOMRef: "pkg:npm/express@4.18.2", Name: "express",
				Version: "4.18.2", Purl: "pkg:npm/express@4.18.2"},
			{Type: "library", BOMRef: "pkg:npm/left-pad@1.3.0", Name: "left-pad",
				Version: "1.3.0", Purl: "pkg:npm/left-pad@1.3.0"},
		},
		Vulnerabilities: []cdx.Vulnerability{
			{ID: "CVE-2020-8203", Affects: []cdx.Affect{{Ref: "pkg:npm/lodash@4.17.20"}}},
			{ID: "CVE-2024-9999", Affects: []cdx.Affect{{Ref: "pkg:npm/express@4.18.2"}}},
			{ID: "CVE-2021-1111", Affects: []cdx.Affect{{Ref: "pkg:npm/left-pad@1.3.0"}}},
			{ID: "CVE-2099-0000", Affects: []cdx.Affect{{Ref: "pkg:npm/lodash@4.17.20"}}},
		},
	}
}

func TestApplyCounts(t *testing.T) {
	bom := testBOM()
	set := setOf(t, "vendor.openvex.json")
	res := Apply(bom, set)

	if res.Total != 4 {
		t.Errorf("Total = %d, want 4", res.Total)
	}
	// not_affected on lodash and fixed on left-pad close two.
	if res.Suppressed != 2 {
		t.Errorf("Suppressed = %d, want 2", res.Suppressed)
	}
	// affected on express annotates without closing; CVE-2099-0000 has no
	// statement at all. Both remain live.
	if res.Annotated != 1 {
		t.Errorf("Annotated = %d, want 1", res.Annotated)
	}
	if res.Effective != 2 {
		t.Errorf("Effective = %d, want 2", res.Effective)
	}
	if res.Total != res.Suppressed+res.Effective {
		t.Errorf("total (%d) != suppressed (%d) + effective (%d)",
			res.Total, res.Suppressed, res.Effective)
	}
}

// TestApplyNeverDeletes is the governing rule: a suppressed finding is
// annotated, not removed. A count that silently went down cannot be audited,
// re-evaluated when the statement expires, or explained to a reviewer.
func TestApplyNeverDeletes(t *testing.T) {
	bom := testBOM()
	before := len(bom.Vulnerabilities)
	Apply(bom, setOf(t, "vendor.openvex.json"))
	if len(bom.Vulnerabilities) != before {
		t.Fatalf("vulnerabilities went from %d to %d; VEX must annotate, never delete",
			before, len(bom.Vulnerabilities))
	}
}

func TestApplyWritesAnalysisAndProvenance(t *testing.T) {
	bom := testBOM()
	Apply(bom, setOf(t, "vendor.openvex.json"))

	var suppressed *cdx.Vulnerability
	for i := range bom.Vulnerabilities {
		if bom.Vulnerabilities[i].ID == "CVE-2020-8203" {
			suppressed = &bom.Vulnerabilities[i]
		}
	}
	if suppressed == nil {
		t.Fatal("CVE-2020-8203 missing")
	}
	if suppressed.Analysis == nil {
		t.Fatal("no analysis block written")
	}
	if suppressed.Analysis.State != "not_affected" {
		t.Errorf("state = %q", suppressed.Analysis.State)
	}
	if suppressed.Analysis.Justification != "vulnerable_code_not_in_execute_path" {
		t.Errorf("justification = %q", suppressed.Analysis.Justification)
	}

	props := map[string]string{}
	for _, p := range suppressed.Properties {
		props[p.Name] = p.Value
	}
	for _, name := range []string{PropVEXSource, PropVEXAuthor, PropVEXBasis, PropVEXExplain} {
		if props[name] == "" {
			t.Errorf("%s is empty — a suppressed finding must be traceable to its statement", name)
		}
	}
}

// TestApplyJustificationOnlyOnNotAffected pins a schema constraint: CycloneDX
// only permits impactAnalysisJustification on not_affected, and writing it
// elsewhere produces a document that fails validation.
func TestApplyJustificationOnlyOnNotAffected(t *testing.T) {
	doc, err := LoadBytes([]byte(`{
	  "@context":"https://openvex.dev/ns/v0.2.0","@id":"x","author":"a","version":1,
	  "statements":[{
	    "vulnerability":{"name":"CVE-2020-8203"},"status":"fixed",
	    "justification":"component_not_present",
	    "products":[{"@id":"pkg:npm/lodash@4.17.20"}]
	  }]
	}`), "")
	if err != nil {
		t.Fatal(err)
	}
	bom := testBOM()
	Apply(bom, NewSet([]*Document{doc}))

	for _, v := range bom.Vulnerabilities {
		if v.ID != "CVE-2020-8203" {
			continue
		}
		if v.Analysis.State != "resolved" {
			t.Errorf("state = %q, want resolved", v.Analysis.State)
		}
		if v.Analysis.Justification != "" {
			t.Errorf("justification %q written on a non-not_affected state; this fails CycloneDX validation",
				v.Analysis.Justification)
		}
	}
}

// TestApplyUnmatchedIsReported covers the single most common reason VEX appears
// not to work — statements about a different product.
func TestApplyUnmatchedIsReported(t *testing.T) {
	bom := &cdx.BOM{BOMFormat: "CycloneDX", SpecVersion: "1.6", Version: 1}
	res := Apply(bom, setOf(t, "vendor.openvex.json"))
	if res.Unmatched != 3 {
		t.Errorf("Unmatched = %d, want 3 — a statement that reached nothing must be surfaced", res.Unmatched)
	}
	if res.Suppressed != 0 || res.Total != 0 {
		t.Errorf("res = %+v", res)
	}
}

func TestApplyNilSafe(t *testing.T) {
	if res := Apply(nil, setOf(t, "vendor.openvex.json")); res == nil {
		t.Fatal("Apply(nil, set) returned nil")
	}
	bom := testBOM()
	res := Apply(bom, NewSet(nil))
	if res.Total != 4 || res.Effective != 4 || res.Suppressed != 0 {
		t.Errorf("an empty statement set changed the counts: %+v", res)
	}
}

func TestSuppressedIDs(t *testing.T) {
	bom := testBOM()
	res := Apply(bom, setOf(t, "vendor.openvex.json"))
	ids := res.SuppressedIDs()
	if len(ids) != 2 {
		t.Fatalf("SuppressedIDs = %v, want 2", ids)
	}
	// Sorted, so downstream output is stable.
	if ids[0] > ids[1] {
		t.Errorf("SuppressedIDs not sorted: %v", ids)
	}
}
