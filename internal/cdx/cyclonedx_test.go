package cdx

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestAnalysisForStateChange_FixedUsesResponseNotJustification guards the bug
// where a "fixed" finding emitted analysis.justification="update". "update" is
// an impactAnalysisResponse value, not a justification, and putting it in
// justification fails CycloneDX schema validation (#/vulnerabilities/.../analysis/justification).
func TestAnalysisForStateChange_FixedUsesResponseNotJustification(t *testing.T) {
	a := AnalysisForStateChange("fixed", "No longer reported by upstream source")
	if a == nil {
		t.Fatal("expected analysis for status=fixed, got nil")
	}
	if a.State != "resolved" {
		t.Errorf("state = %q, want resolved", a.State)
	}
	if len(a.Response) != 1 || a.Response[0] != "update" {
		t.Errorf("response = %v, want [update]", a.Response)
	}
	if a.Justification != "" {
		t.Errorf("justification = %q, want empty (justification only applies to not_affected)", a.Justification)
	}

	out, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	js := string(out)
	if !strings.Contains(js, `"response":["update"]`) {
		t.Errorf("serialized analysis missing response: %s", js)
	}
	if strings.Contains(js, `"justification"`) {
		t.Errorf("serialized analysis must not contain justification: %s", js)
	}
}

func TestAnalysisForStateChange_UnderInvestigation(t *testing.T) {
	a := AnalysisForStateChange("under_investigation", "triaging")
	if a == nil || a.State != "in_triage" {
		t.Fatalf("state = %+v, want in_triage", a)
	}
	if len(a.Response) != 0 {
		t.Errorf("response = %v, want none for in_triage", a.Response)
	}
}

func TestAnalysisForStateChange_UnknownStatusIsNil(t *testing.T) {
	if a := AnalysisForStateChange("affected", ""); a != nil {
		t.Errorf("expected nil analysis for unmapped status, got %+v", a)
	}
}

func minimalBOM(analysis *Analysis) *BOM {
	return &BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.7",
		SerialNumber: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
		Version:      1,
		Vulnerabilities: []Vulnerability{
			{ID: "CVE-2024-0001", Analysis: analysis},
		},
	}
}

// TestMarshalValidatedJSON_AcceptsResolvedResponse confirms a BOM built via the
// fixed generator path validates and serialises with the response array.
func TestMarshalValidatedJSON_AcceptsResolvedResponse(t *testing.T) {
	data, err := minimalBOM(AnalysisForStateChange("fixed", "upgraded")).MarshalValidatedJSON()
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
	if !strings.Contains(string(data), `"response"`) {
		t.Errorf("serialised BOM missing response: %s", data)
	}
}

// TestMarshalValidatedJSON_RejectsInvalidJustification is the write-time guard:
// the old bug (justification="update") must fail before anything is written.
func TestMarshalValidatedJSON_RejectsInvalidJustification(t *testing.T) {
	_, err := minimalBOM(&Analysis{State: "resolved", Justification: "update"}).MarshalValidatedJSON()
	if err == nil {
		t.Fatal("expected validation error for justification=update, got nil")
	}
	if !strings.Contains(err.Error(), "schema validation") {
		t.Errorf("unexpected error message: %v", err)
	}
}
