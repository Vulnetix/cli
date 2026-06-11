package schema

import (
	"testing"
)

func TestSupportedVersions(t *testing.T) {
	versions := SupportedVersions()
	expected := []string{"1.7", "1.6", "1.5", "1.4", "1.3", "1.2"}
	if len(versions) != len(expected) {
		t.Fatalf("expected %d versions, got %d: %v", len(expected), len(versions), versions)
	}
	for i, v := range expected {
		if versions[i] != v {
			t.Fatalf("versions[%d]: expected %q, got %q", i, v, versions[i])
		}
	}
}

func TestSupportedVersionsAscending(t *testing.T) {
	versions := SupportedVersionsAscending()
	expected := []string{"1.2", "1.3", "1.4", "1.5", "1.6", "1.7"}
	for i, v := range expected {
		if versions[i] != v {
			t.Fatalf("versions[%d]: expected %q, got %q", i, v, versions[i])
		}
	}
}

func TestSupportedVersions_ReturnsCopy(t *testing.T) {
	v1 := SupportedVersions()
	v2 := SupportedVersions()
	if &v1[0] == &v2[0] {
		t.Fatal("SupportedVersions should return a new copy each call")
	}
}

func TestValidateCDX_InvalidJSON(t *testing.T) {
	_, err := ValidateCDX([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestValidateCDX_ValidBOM15(t *testing.T) {
	bom := []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-01T00:00:00Z",
    "component": {
      "type": "application",
      "name": "test-app"
    }
  }
}`)
	version, err := ValidateCDX(bom)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != "1.5" {
		t.Fatalf("expected version 1.5, got %q", version)
	}
}

func TestValidateCDX_ValidBOM14(t *testing.T) {
	bom := []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
      "type": "application",
      "name": "test-app"
    }
  }
}`)
	version, err := ValidateCDX(bom)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != "1.4" {
		t.Fatalf("expected version 1.4, got %q", version)
	}
}

func TestValidateCycloneDX_UnsupportedVersionViolation(t *testing.T) {
	bom := []byte(`{"bomFormat":"CycloneDX","specVersion":"9.9"}`)
	version, violations, err := ValidateCycloneDX(bom)
	if err != nil {
		t.Fatalf("unexpected fatal error: %v", err)
	}
	if version != "9.9" {
		t.Fatalf("expected version 9.9, got %q", version)
	}
	if len(violations) != 1 || violations[0].Path != "/specVersion" {
		t.Fatalf("expected /specVersion violation, got %#v", violations)
	}
}

func TestValidateCycloneDX_NonCycloneDXJSON(t *testing.T) {
	version, violations, err := ValidateCycloneDX([]byte(`{"spdxVersion":"SPDX-2.3"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != "" || len(violations) != 0 {
		t.Fatalf("expected non-CDX pass-through, got version=%q violations=%#v", version, violations)
	}
}

func TestValidateCDX_EmptyObject(t *testing.T) {
	_, err := ValidateCDX([]byte("{}"))
	if err == nil {
		t.Fatal("expected error for empty object")
	}
}

func TestEnsureCompiled_Idempotent(t *testing.T) {
	err1 := ensureCompiled()
	err2 := ensureCompiled()
	if (err1 == nil) != (err2 == nil) {
		t.Fatal("ensureCompiled should be idempotent")
	}
}
