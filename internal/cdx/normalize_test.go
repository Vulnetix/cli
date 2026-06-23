package cdx

import "testing"

func TestNormalizeForSchema_SeverityUnscoredBecomesUnknown(t *testing.T) {
	bom := &BOM{
		Vulnerabilities: []Vulnerability{
			{ID: "CVE-1", Ratings: []Rating{{Severity: "unscored"}, {Severity: "HIGH"}, {Severity: ""}}},
		},
	}
	bom.NormalizeForSchema()
	got := bom.Vulnerabilities[0].Ratings
	if got[0].Severity != "unknown" {
		t.Errorf("unscored → %q, want unknown", got[0].Severity)
	}
	if got[1].Severity != "high" {
		t.Errorf("HIGH → %q, want high (lowercased valid value)", got[1].Severity)
	}
	if got[2].Severity != "" {
		t.Errorf("empty → %q, want empty (omitted)", got[2].Severity)
	}
}

// TestNormalizeForSchema_LegacyJustificationUpdate covers the merge-perpetuation
// case: an old on-disk SBOM with analysis.justification="update" must be healed
// to response=["update"] so a rescan does not keep failing validation.
func TestNormalizeForSchema_LegacyJustificationUpdate(t *testing.T) {
	bom := &BOM{
		Vulnerabilities: []Vulnerability{
			{ID: "CVE-1", Analysis: &Analysis{State: "resolved", Justification: "update", Detail: "x"}},
		},
	}
	bom.NormalizeForSchema()
	a := bom.Vulnerabilities[0].Analysis
	if a.Justification != "" {
		t.Errorf("justification = %q, want cleared", a.Justification)
	}
	if len(a.Response) != 1 || a.Response[0] != "update" {
		t.Errorf("response = %v, want [update]", a.Response)
	}
}

func TestNormalizeForSchema_ValidJustificationPreserved(t *testing.T) {
	bom := &BOM{
		Vulnerabilities: []Vulnerability{
			{ID: "CVE-1", Analysis: &Analysis{State: "not_affected", Justification: "code_not_present"}},
		},
	}
	bom.NormalizeForSchema()
	if bom.Vulnerabilities[0].Analysis.Justification != "code_not_present" {
		t.Errorf("valid justification should be preserved, got %q", bom.Vulnerabilities[0].Analysis.Justification)
	}
}

// TestNormalizeForSchema_HealsThenValidates ties it together: a BOM with both
// legacy bad values validates clean after normalization.
func TestNormalizeForSchema_HealsThenValidates(t *testing.T) {
	bom := &BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.7",
		SerialNumber: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
		Version:      1,
		Vulnerabilities: []Vulnerability{
			{ID: "CVE-1", Ratings: []Rating{{Severity: "unscored"}}, Analysis: &Analysis{State: "resolved", Justification: "update"}},
		},
	}
	if _, err := bom.MarshalValidatedJSON(); err == nil {
		t.Fatal("expected pre-normalization BOM to fail validation")
	}
	bom.NormalizeForSchema()
	if _, err := bom.MarshalValidatedJSON(); err != nil {
		t.Fatalf("post-normalization BOM should validate, got: %v", err)
	}
}
