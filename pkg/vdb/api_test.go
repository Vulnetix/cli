package vdb

import (
	"encoding/json"
	"testing"
)

func TestCVEInfo(t *testing.T) {
	c := CVEInfo{Data: map[string]interface{}{"id": "CVE-0001"}}
	if c.Data == nil {
		t.Error("expected non-nil Data")
	}
}

func TestEcosystemsResponse(t *testing.T) {
	r := EcosystemsResponse{
		Timestamp:  1234567890,
		Ecosystems: []Ecosystem{{Name: "npm", Count: 100}},
	}
	if r.Timestamp != 1234567890 {
		t.Errorf("expected 1234567890, got %d", r.Timestamp)
	}
	if len(r.Ecosystems) != 1 || r.Ecosystems[0].Name != "npm" {
		t.Errorf("unexpected ecosystems: %+v", r.Ecosystems)
	}
}

func TestVersionSource_UnmarshalJSON_String(t *testing.T) {
	data := []byte(`"nvd"`)
	var vs VersionSource
	if err := json.Unmarshal(data, &vs); err != nil {
		t.Fatalf("failed to unmarshal string: %v", err)
	}
	if vs.SourceTable != "nvd" {
		t.Errorf("expected 'nvd', got %q", vs.SourceTable)
	}
}

func TestVersionSource_UnmarshalJSON_Object(t *testing.T) {
	data := []byte(`{"sourceTable":"cve","sourceId":"CVE-0001","metadata":{"key":"val"}}`)
	var vs VersionSource
	if err := json.Unmarshal(data, &vs); err != nil {
		t.Fatalf("failed to unmarshal object: %v", err)
	}
	if vs.SourceTable != "cve" {
		t.Errorf("expected 'cve', got %q", vs.SourceTable)
	}
	if vs.SourceID != "CVE-0001" {
		t.Errorf("expected 'CVE-0001', got %q", vs.SourceID)
	}
}

func TestGCVEIssuancesResponse(t *testing.T) {
	r := GCVEIssuancesResponse{
		Year:  2024,
		Month: 1,
		Total: 10,
		Identifiers: []GCVEIssuanceIdentifier{
			{GcveID: "GCVE-2024-0001", CveID: "CVE-2024-0001"},
		},
	}
	if r.Year != 2024 || r.Month != 1 {
		t.Errorf("unexpected year/month: %d/%d", r.Year, r.Month)
	}
	if len(r.Identifiers) != 1 {
		t.Errorf("expected 1 identifier, got %d", len(r.Identifiers))
	}
}

func TestV2QueryString(t *testing.T) {
	p := V2QueryParams{
		Ecosystem:   "npm",
		PackageName: "express",
		Limit:       10,
	}
	qs := v2QueryString(p)
	if qs == "" {
		t.Error("expected non-empty query string")
	}
	if qs[0] != '?' {
		t.Errorf("expected '?' prefix, got %q", qs)
	}
}

func TestV2QueryString_Empty(t *testing.T) {
	qs := v2QueryString(V2QueryParams{})
	if qs != "" {
		t.Errorf("expected empty string, got %q", qs)
	}
}

func TestV2QueryParams(t *testing.T) {
	p := V2QueryParams{
		Ecosystem:   "npm",
		PackageName: "lodash",
		Vendor:      "test-vendor",
		Product:     "test-product",
		Distro:      "ubuntu",
		Purl:        "pkg:npm/lodash@4.17.21",
		Limit:       50,
		Offset:      0,
	}
	_ = p
}

func TestV2RemediationParams(t *testing.T) {
	p := V2RemediationParams{
		V2QueryParams: V2QueryParams{
			Ecosystem: "npm",
		},
		CurrentVersion:           "4.17.20",
		PackageManager:           "npm",
		ContainerImage:           "node:18",
		IncludeGuidance:          true,
		IncludeVerificationSteps: true,
	}
	if p.CurrentVersion != "4.17.20" {
		t.Errorf("unexpected version: %q", p.CurrentVersion)
	}
	if !p.IncludeGuidance {
		t.Error("expected IncludeGuidance true")
	}
}

func TestProductVersionsResponse(t *testing.T) {
	r := ProductVersionsResponse{
		PackageName: "express",
		Total:       100,
		Limit:       10,
		Offset:      0,
		HasMore:     true,
	}
	if r.PackageName != "express" {
		t.Errorf("expected 'express', got %q", r.PackageName)
	}
	if !r.HasMore {
		t.Error("expected HasMore true")
	}
}

func TestVulnerabilitiesResponse(t *testing.T) {
	r := VulnerabilitiesResponse{
		PackageName: "express",
		TotalCVEs:   5,
		Total:       5,
	}
	if r.PackageName != "express" || r.TotalCVEs != 5 {
		t.Errorf("unexpected values: %+v", r)
	}
}
