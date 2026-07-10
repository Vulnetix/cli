package cdx

import "testing"

// A resolution must annotate the vulnerability the previous run left in the BOM,
// not append a twin — otherwise the document asserts the same id is both open
// and resolved.
func TestApplyVEXAnalysis_FoldsOntoExistingEntry(t *testing.T) {
	bom := &BOM{Vulnerabilities: []Vulnerability{
		{ID: "CVE-1", BOMRef: "CVE-1", Source: &Source{Name: "vulnetix-sca"}},
	}}
	ApplyVEXAnalysis(bom, []Vulnerability{{
		ID:         "CVE-1",
		BOMRef:     "CVE-1",
		Analysis:   AnalysisForStateChange("fixed", "dependency removed"),
		Properties: []Property{{Name: "vulnetix:vex-auto", Value: "true"}},
	}})

	if len(bom.Vulnerabilities) != 1 {
		t.Fatalf("expected the entry to be annotated in place, got %d entries", len(bom.Vulnerabilities))
	}
	v := bom.Vulnerabilities[0]
	if v.Analysis == nil || v.Analysis.State != "resolved" {
		t.Errorf("analysis not applied: %+v", v.Analysis)
	}
	if len(v.Properties) != 1 || v.Properties[0].Name != "vulnetix:vex-auto" {
		t.Errorf("properties not merged: %+v", v.Properties)
	}
}

func TestApplyVEXAnalysis_AppendsUnknownID(t *testing.T) {
	bom := &BOM{Vulnerabilities: []Vulnerability{{ID: "CVE-1"}}}
	ApplyVEXAnalysis(bom, []Vulnerability{
		{ID: "CVE-2", Analysis: AnalysisForStateChange("fixed", "gone")},
	})
	if len(bom.Vulnerabilities) != 2 {
		t.Fatalf("expected the new id to be appended, got %d entries", len(bom.Vulnerabilities))
	}
}

func TestApplyVEXAnalysis_DoesNotDuplicateProperties(t *testing.T) {
	bom := &BOM{Vulnerabilities: []Vulnerability{{
		ID:         "CVE-1",
		Properties: []Property{{Name: "vulnetix:vex-auto", Value: "true"}},
	}}}
	ApplyVEXAnalysis(bom, []Vulnerability{{
		ID:         "CVE-1",
		Properties: []Property{{Name: "vulnetix:vex-auto", Value: "true"}},
	}})
	if got := len(bom.Vulnerabilities[0].Properties); got != 1 {
		t.Errorf("property count = %d, want 1", got)
	}
}

func TestApplyVEXAnalysis_NilSafe(t *testing.T) {
	ApplyVEXAnalysis(nil, []Vulnerability{{ID: "CVE-1"}})
	bom := &BOM{}
	ApplyVEXAnalysis(bom, nil)
	if len(bom.Vulnerabilities) != 0 {
		t.Error("empty input must not touch the BOM")
	}
}
