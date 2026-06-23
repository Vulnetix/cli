package cyclonedx

import (
	"strings"
	"testing"
)

const resolvedResponseBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "version": 1,
  "vulnerabilities": [
    {"id": "CVE-2024-0001", "analysis": {"state": "resolved", "response": ["update"], "detail": "fixed by upgrade"}}
  ]
}`

const justificationUpdateBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "version": 1,
  "vulnerabilities": [
    {"id": "CVE-2024-0001", "analysis": {"state": "resolved", "justification": "update", "detail": "fixed by upgrade"}}
  ]
}`

// TestValidateCycloneDX_ResolvedResponseIsValid is the positive side of the
// generator fix: state=resolved with response=["update"] must validate clean.
func TestValidateCycloneDX_ResolvedResponseIsValid(t *testing.T) {
	version, violations, err := ValidateCycloneDX([]byte(resolvedResponseBOM))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != "1.7" {
		t.Errorf("version = %q, want 1.7", version)
	}
	if len(violations) != 0 {
		t.Fatalf("expected no violations, got %+v", violations)
	}
}

// TestValidateCycloneDX_JustificationUpdateRejected reproduces the original bug:
// "update" in analysis.justification must be rejected (it is a response value).
func TestValidateCycloneDX_JustificationUpdateRejected(t *testing.T) {
	version, violations, err := ValidateCycloneDX([]byte(justificationUpdateBOM))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != "1.7" {
		t.Errorf("version = %q, want 1.7", version)
	}
	if len(violations) == 0 {
		t.Fatal("expected violations for invalid justification, got none")
	}
	joined := ""
	for _, v := range violations {
		joined += v.Path + " " + v.Message + "\n"
	}
	if !strings.Contains(joined, "justification") {
		t.Errorf("expected a justification violation, got:\n%s", joined)
	}
}

func TestValidateCycloneDX_NonCycloneDXIsPassthrough(t *testing.T) {
	version, violations, err := ValidateCycloneDX([]byte(`{"hello":"world"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != "" || len(violations) != 0 {
		t.Errorf("non-CycloneDX should return empty version and no violations, got version=%q violations=%+v", version, violations)
	}
}

func TestValidateCycloneDX_UnsupportedVersion(t *testing.T) {
	doc := `{"bomFormat":"CycloneDX","specVersion":"9.9","version":1}`
	version, violations, err := ValidateCycloneDX([]byte(doc))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != "9.9" {
		t.Errorf("version = %q, want 9.9", version)
	}
	if len(violations) != 1 || violations[0].Path != "/specVersion" {
		t.Fatalf("expected one /specVersion violation, got %+v", violations)
	}
}

func TestSupportedVersionsOrdering(t *testing.T) {
	desc := SupportedVersions()
	if desc[0] != "2.0" || desc[len(desc)-1] != "1.2" {
		t.Errorf("SupportedVersions should be highest-first, got %v", desc)
	}
	asc := SupportedVersionsAscending()
	if asc[0] != "1.2" || asc[len(asc)-1] != "2.0" {
		t.Errorf("SupportedVersionsAscending should be lowest-first, got %v", asc)
	}
}
