package cyclonedx

import (
	"encoding/json"
	"strings"
	"testing"
)

// CycloneDX 1.2–1.4 carry metadata.tools as an array of tool objects; 1.5+ use
// an object with a components[] list. ParseCDX must accept both, and tool
// metadata being ancillary must never fail the whole ingestion.
func TestParseCDX_ToolsArrayForm(t *testing.T) {
	data := []byte(`{
		"bomFormat":"CycloneDX","specVersion":"1.4","serialNumber":"urn:uuid:00000000-0000-4000-8000-000000000014","version":1,
		"metadata":{
			"timestamp":"2026-05-30T00:00:00Z",
			"tools":[{"vendor":"Vulnetix","name":"vulnetix-sca","version":"v3.9.1","hashes":[{"alg":"SHA-256","content":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}]}]
		},
		"components":[{"type":"library","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21"}]
	}`)
	bom, err := ParseCDX(data)
	if err != nil {
		t.Fatalf("array-form tools must not fail parse: %v", err)
	}
	if bom.Metadata.Tools == nil || len(bom.Metadata.Tools.Components) != 1 {
		t.Fatalf("expected 1 tool component, got %+v", bom.Metadata.Tools)
	}
	tm := ExtractToolMeta(bom)
	if tm.ToolName != "vulnetix-sca" || tm.ToolVersion != "v3.9.1" || tm.ToolVendor != "Vulnetix" ||
		tm.ToolHash != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Fatalf("array-form tool meta mismatch: %+v", tm)
	}
	if len(bom.Components) != 1 || bom.Components[0].Name != "lodash" {
		t.Fatalf("components should still parse: %+v", bom.Components)
	}
}

func TestParseCDX_ToolsObjectForm(t *testing.T) {
	data := []byte(`{
		"bomFormat":"CycloneDX","specVersion":"1.7","serialNumber":"urn:uuid:00000000-0000-4000-8000-000000000017","version":1,
		"metadata":{
			"timestamp":"2026-05-30T00:00:00Z",
			"tools":{"components":[{"type":"application","name":"vulnetix-sca","version":"v3.9.1","publisher":"Vulnetix"}]}
		},
		"components":[{"type":"library","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"}]
	}`)
	bom, err := ParseCDX(data)
	if err != nil {
		t.Fatalf("object-form tools must parse: %v", err)
	}
	tm := ExtractToolMeta(bom)
	if tm.ToolName != "vulnetix-sca" || tm.ToolVendor != "Vulnetix" {
		t.Fatalf("object-form tool meta mismatch: %+v", tm)
	}
}

// A tools shape we don't model (e.g. a bare string) must be tolerated, not fatal.
func TestCDXTools_UnknownShapeIsTolerated(t *testing.T) {
	data := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"tools":"acme-tool"},"components":[]}`)
	var bom CDXBom
	err := json.Unmarshal(data, &bom)
	if err != nil {
		t.Fatalf("unknown tools shape must not fail parse: %v", err)
	}
	if bom.Metadata.Tools != nil && len(bom.Metadata.Tools.Components) != 0 {
		t.Fatalf("unknown tools shape should yield no components")
	}
}

// Every supported version validates against its official schema and then parses
// through the same flat structs for fields this package consumes.
func TestParseCDX_AllSpecVersions(t *testing.T) {
	versions := []string{"1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "2.0"}
	uuids := map[string]string{
		"1.2": "00000000-0000-4000-8000-000000000012",
		"1.3": "00000000-0000-4000-8000-000000000013",
		"1.4": "00000000-0000-4000-8000-000000000014",
		"1.5": "00000000-0000-4000-8000-000000000015",
		"1.6": "00000000-0000-4000-8000-000000000016",
		"1.7": "00000000-0000-4000-8000-000000000017",
		"2.0": "00000000-0000-4000-8000-000000000020",
	}
	for _, v := range versions {
		formatField := `"bomFormat":"CycloneDX"`
		if v == "2.0" {
			formatField = `"specFormat":"CycloneDX"`
		}
		data := []byte(`{
			` + formatField + `,"specVersion":"` + v + `","serialNumber":"urn:uuid:` + uuids[v] + `","version":1,
			"metadata":{"timestamp":"2026-05-30T00:00:00Z",
				"component":{"type":"application","bom-ref":"root","name":"app","version":"1.0.0"}},
			"components":[
				{"type":"library","bom-ref":"c1","name":"openssl","version":"3.0.1","purl":"pkg:generic/openssl@3.0.1",
				 "licenses":[{"license":{"id":"Apache-2.0"}}]}
			]
		}`)
		bom, err := ParseCDX(data)
		if err != nil {
			t.Fatalf("spec %s: parse failed: %v", v, err)
		}
		if bom.SpecVersion != v {
			t.Fatalf("spec %s: specVersion mismatch: %q", v, bom.SpecVersion)
		}
		if bom.BomFormat != "CycloneDX" {
			t.Fatalf("spec %s: bom format compatibility mismatch: %q", v, bom.BomFormat)
		}
		if len(bom.Components) != 1 || bom.Components[0].Name != "openssl" {
			t.Fatalf("spec %s: components mismatch: %+v", v, bom.Components)
		}
		if ExtractLicense(bom.Components[0]) != "Apache-2.0" {
			t.Fatalf("spec %s: license mismatch", v)
		}
	}
}

// dependencies[].dependsOn (1.4+) and the legacy dependencies[].dependencies
// (1.2–1.3) must both populate CDXDependency.DependsOn.
func TestParseCDX_DependsOnBothForms(t *testing.T) {
	modern := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6",
		"version":1,"dependencies":[{"ref":"root","dependsOn":["a","b"]}]}`)
	bom, err := ParseCDX(modern)
	if err != nil {
		t.Fatalf("modern dependsOn parse: %v", err)
	}
	if len(bom.Dependencies) != 1 || bom.Dependencies[0].Ref != "root" ||
		len(bom.Dependencies[0].DependsOn) != 2 {
		t.Fatalf("modern dependsOn mismatch: %+v", bom.Dependencies)
	}

	legacy := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.3",
		"version":1,"dependencies":[{"ref":"root","dependencies":["a","b","c"]}]}`)
	bom, err = ParseCDX(legacy)
	if err != nil {
		t.Fatalf("legacy dependencies parse: %v", err)
	}
	if len(bom.Dependencies[0].DependsOn) != 3 {
		t.Fatalf("legacy dependencies should coalesce into DependsOn: %+v", bom.Dependencies)
	}
}

func TestValidateCDX_RejectsInvalidSchema(t *testing.T) {
	data := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.7","version":1,"unknown":true}`)
	err := ValidateCDX(data)
	if err == nil {
		t.Fatal("expected schema validation error")
	}
	if !strings.Contains(err.Error(), "schema validation failed") {
		t.Fatalf("expected schema validation failure, got %v", err)
	}
}

func TestDetectSpecVersion_RejectsUnsupportedVersion(t *testing.T) {
	data := []byte(`{"specFormat":"CycloneDX","specVersion":"2.1","version":1}`)
	_, err := DetectSpecVersion(data)
	if err == nil {
		t.Fatal("expected unsupported version error")
	}
	if !strings.Contains(err.Error(), `unsupported CycloneDX specVersion "2.1"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractEcosystemAndLicenses(t *testing.T) {
	if got := ExtractEcosystem("pkg:npm/lodash@4.17.21"); got != "npm" {
		t.Fatalf("ExtractEcosystem npm: got %q", got)
	}
	if got := ExtractEcosystem("not-a-purl"); got != "" {
		t.Fatalf("ExtractEcosystem non-purl: got %q", got)
	}

	bom := &CDXBom{
		Metadata: CDXMetadata{Component: &CDXComponent{
			Name: "app", Licenses: []struct {
				License struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"license"`
			}{{License: struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}{ID: "MIT"}}},
		}},
		Components: []CDXComponent{
			{Name: "a", Purl: "pkg:npm/a@1.0.0"},
			{Name: "b", Purl: "pkg:pypi/b@2.0.0"},
			{Name: "c", Purl: "pkg:npm/c@3.0.0"}, // duplicate ecosystem
		},
	}
	ecos := DistinctEcosystems(bom)
	if len(ecos) != 2 {
		t.Fatalf("DistinctEcosystems expected [npm pypi], got %v", ecos)
	}
	lics := ExtractLicenses(bom)
	if len(lics) != 1 || lics[0].SPDXID != "MIT" {
		t.Fatalf("ExtractLicenses expected MIT, got %+v", lics)
	}
}
