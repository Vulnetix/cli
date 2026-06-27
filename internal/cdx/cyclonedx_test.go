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

// stubCanonical is a tiny SPDX oracle for unit tests: it recognises a fixed set
// of ids case-insensitively and canonicalises their spelling, mirroring
// license.CanonicalSPDXID without the import cycle.
func stubCanonical(id string) string {
	switch strings.ToLower(id) {
	case "mit":
		return "MIT"
	case "apache-2.0":
		return "Apache-2.0"
	}
	return ""
}

// TestPopulateLicenses_DemotesUnrecognisedIDToName is the regression guard for
// the canonical SBOM write: an unrecognised SPDX id from the license detector
// must land in the free-text license.name, never the enum-constrained
// license.id, so .vulnetix/sbom.cdx.json keeps passing schema validation.
func TestPopulateLicenses_DemotesUnrecognisedIDToName(t *testing.T) {
	bom := &BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.7",
		Version:     1,
		Components: []Component{
			{Type: "library", Name: "valid", Version: "1.0.0"},
			{Type: "library", Name: "lowercase", Version: "1.0.0"},
			{Type: "library", Name: "bogus", Version: "1.0.0"},
			{Type: "library", Name: "dual", Version: "1.0.0"},
			{Type: "library", Name: "exc", Version: "1.0.0"},
		},
	}
	licenseMap := map[string]string{
		"valid@1.0.0":     "MIT",
		"lowercase@1.0.0": "apache-2.0", // recognised but non-canonical case
		"bogus@1.0.0":     "Public Domain",
		"dual@1.0.0":      "MIT OR Apache-2.0",
		"exc@1.0.0":       "GPL-2.0-only WITH Classpath-exception-2.0",
	}
	PopulateLicenses(bom, licenseMap, stubCanonical)

	byName := map[string]LicenseChoice{}
	for _, c := range bom.Components {
		if len(c.Licenses) == 1 {
			byName[c.Name] = c.Licenses[0]
		}
	}

	if lc := byName["valid"]; lc.License == nil || lc.License.ID != "MIT" {
		t.Errorf("valid: want license.id=MIT, got %+v", lc)
	}
	if lc := byName["lowercase"]; lc.License == nil || lc.License.ID != "Apache-2.0" {
		t.Errorf("lowercase: want canonical license.id=Apache-2.0, got %+v", lc)
	}
	if lc := byName["bogus"]; lc.License == nil || lc.License.ID != "" || lc.License.Name != "Public Domain" {
		t.Errorf("bogus: unrecognised id must become license.name, got %+v", lc)
	}
	if lc := byName["dual"]; lc.Expression != "MIT OR Apache-2.0" {
		t.Errorf("dual: want expression, got %+v", lc)
	}
	if lc := byName["exc"]; lc.Expression != "GPL-2.0-only WITH Classpath-exception-2.0" {
		t.Errorf("exc: WITH-expression must use expression field, got %+v", lc)
	}
}
