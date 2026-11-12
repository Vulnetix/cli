package cdx

import (
	"reflect"
	"testing"

	"github.com/vulnetix/cli/v4/internal/scan"
)

func TestDeploymentContextEmpty(t *testing.T) {
	if !(DeploymentContext{}).Empty() {
		t.Error("the zero context is empty")
	}
	if !(DeploymentContext{Tags: map[string]string{}}).Empty() {
		t.Error("an empty tag map is still empty")
	}
	for _, d := range []DeploymentContext{
		{Project: "p"}, {Cluster: "c"}, {Namespace: "n"}, {Environment: "e"},
		{Tags: map[string]string{"team": "x"}},
	} {
		if d.Empty() {
			t.Errorf("%+v is not empty", d)
		}
	}
}

func TestDeploymentContextString(t *testing.T) {
	d := DeploymentContext{
		Project: "payment-service", Namespace: "pay",
		Tags: map[string]string{"zone": "a", "team": "core", "blank": ""},
	}
	// Only the set fields, in field order, then the tags sorted by key; an empty
	// tag value is left out like an empty field.
	want := "project=payment-service namespace=pay team=core zone=a"
	for range 5 {
		if got := d.String(); got != want {
			t.Fatalf("String() = %q, want %q", got, want)
		}
	}
	if got := (DeploymentContext{}).String(); got != "" {
		t.Errorf("empty String() = %q", got)
	}
}

func TestApplyDeploymentContextRoundTrips(t *testing.T) {
	d := DeploymentContext{
		Project: "payment-service", Cluster: "prod-eu", Namespace: "pay", Environment: "production",
		Tags: map[string]string{"team": "core", "zone": "a"},
	}
	bom := &BOM{}
	ApplyDeploymentContext(bom, d)
	if bom.Metadata == nil {
		t.Fatal("metadata is created when absent")
	}
	if got := DeploymentContextFromBOM(bom); !reflect.DeepEqual(got, d) {
		t.Fatalf("read back %+v, want %+v", got, d)
	}

	// Applying again replaces rather than duplicates.
	n := len(bom.Metadata.Properties)
	d2 := d
	d2.Cluster = "prod-us"
	ApplyDeploymentContext(bom, d2)
	if len(bom.Metadata.Properties) != n {
		t.Errorf("re-applying grew the properties from %d to %d", n, len(bom.Metadata.Properties))
	}
	if got := DeploymentContextFromBOM(bom).Cluster; got != "prod-us" {
		t.Errorf("cluster = %q after re-apply", got)
	}
}

func TestApplyDeploymentContextSkipsEmpty(t *testing.T) {
	ApplyDeploymentContext(nil, DeploymentContext{Project: "p"}) // must not panic

	bom := &BOM{}
	ApplyDeploymentContext(bom, DeploymentContext{})
	if bom.Metadata != nil {
		t.Error("an empty context must not create metadata")
	}

	ApplyDeploymentContext(bom, DeploymentContext{Environment: "staging"})
	if len(bom.Metadata.Properties) != 1 || bom.Metadata.Properties[0].Name != PropDeploymentEnvironment {
		t.Errorf("only the set field is written: %+v", bom.Metadata.Properties)
	}
}

func TestDeploymentContextFromBOMWithoutLabels(t *testing.T) {
	if got := DeploymentContextFromBOM(nil); !got.Empty() {
		t.Errorf("nil BOM: %+v", got)
	}
	if got := DeploymentContextFromBOM(&BOM{}); !got.Empty() {
		t.Errorf("nil metadata: %+v", got)
	}
	bom := &BOM{Metadata: &Metadata{}}
	bom.Metadata.SetProperty("vulnetix:other", "x")
	bom.Metadata.SetProperty(PropDeploymentTagPrefix, "no key")
	got := DeploymentContextFromBOM(bom)
	if !got.Empty() || got.Tags != nil {
		t.Errorf("unrelated properties and a tag with no key are not labels: %+v", got)
	}
}

func TestScopeMappers(t *testing.T) {
	for _, tt := range []struct {
		scope, cdxScope, env string
	}{
		{scan.ScopeProduction, "required", "production"},
		{scan.ScopeRuntime, "required", "production"},
		{scan.ScopeDevelopment, "optional", "development"},
		{scan.ScopeTest, "optional", "test"},
		{scan.ScopePeer, "optional", "production"},
		{scan.ScopeOptional, "optional", "production"},
		{scan.ScopeProvided, "optional", "production"},
		{scan.ScopeSystem, "optional", "production"},
		{"", "required", ""},
		{"something-else", "required", ""},
	} {
		if got := mapLocalScopeToCDX(tt.scope); got != tt.cdxScope {
			t.Errorf("mapLocalScopeToCDX(%q) = %q, want %q", tt.scope, got, tt.cdxScope)
		}
		if got := nativeScopeToEnvironment(tt.scope); got != tt.env {
			t.Errorf("nativeScopeToEnvironment(%q) = %q, want %q", tt.scope, got, tt.env)
		}
	}
}

func TestFormatHelpers(t *testing.T) {
	if got := FormatSpec("1.7"); got != "CycloneDX 1.7" {
		t.Errorf("FormatSpec = %q", got)
	}
	if got := ValidSpecVersions(); !reflect.DeepEqual(got, []string{"1.2", "1.3", "1.4", "1.5", "1.6", "1.7"}) {
		t.Errorf("ValidSpecVersions = %v", got)
	}
	for _, tt := range []struct {
		in   string
		spec string
		raw  bool
	}{
		{"cdx", "1.7", false}, {"CDX17", "1.7", false}, {"cyclonedx17", "1.7", false}, {"1.7", "1.7", false},
		{"cdx16", "1.6", false}, {"CycloneDX16", "1.6", false}, {"1.6", "1.6", false},
		{"cdx15", "1.5", false}, {"1.5", "1.5", false},
		{"cdx14", "1.4", false}, {"1.4", "1.4", false},
		{"cdx13", "1.3", false}, {"1.3", "1.3", false},
		{"cdx12", "1.2", false}, {"1.2", "1.2", false},
		{"json", "", true}, {"RAW", "", true},
		{"", "1.7", false}, {"spdx", "1.7", false},
	} {
		spec, raw := NormalizeFormat(tt.in)
		if spec != tt.spec || raw != tt.raw {
			t.Errorf("NormalizeFormat(%q) = (%q, %v), want (%q, %v)", tt.in, spec, raw, tt.spec, tt.raw)
		}
	}
}

// mergeComponentGaps fills only what the existing component lacks, and unions
// its lists keeping the existing entries first.
func TestMergeComponentGapsFillsOnlyEmptyFields(t *testing.T) {
	existing := Component{
		Name: "lodash", Version: "4.17.20",
		Hashes:     []Hash{{Alg: "SHA-256", Content: "aa"}},
		Authors:    []OrganizationalContact{{Name: "A", Email: "a@x"}},
		Properties: []Property{{Name: "k", Value: "v"}},
	}
	incoming := Component{
		Type: "library", BOMRef: "pkg:npm/lodash@4.17.20", Name: "other", Version: "9.9.9",
		Description: "utility", Scope: "required", Purl: "pkg:npm/lodash@4.17.20",
		Hashes:             []Hash{{Alg: "SHA-256", Content: "aa"}, {Alg: "SHA-512", Content: "bb"}},
		Authors:            []OrganizationalContact{{Name: "A", Email: "a@x"}, {Name: "B"}},
		ExternalReferences: []ExternalReference{{Type: "website", URL: "https://lodash.com"}},
		Properties:         []Property{{Name: "k", Value: "v"}, {Name: "k", Value: "w"}},
	}
	mergeComponentGaps(&existing, incoming)

	if existing.Name != "lodash" || existing.Version != "4.17.20" {
		t.Errorf("set fields must be kept: %s@%s", existing.Name, existing.Version)
	}
	if existing.Type != "library" || existing.BOMRef != incoming.BOMRef || existing.Description != "utility" ||
		existing.Scope != "required" || existing.Purl != incoming.Purl {
		t.Errorf("empty fields must be filled: %+v", existing)
	}
	if len(existing.Hashes) != 2 || existing.Hashes[0].Content != "aa" || existing.Hashes[1].Content != "bb" {
		t.Errorf("hashes = %+v", existing.Hashes)
	}
	if len(existing.Authors) != 2 || existing.Authors[1].Name != "B" {
		t.Errorf("authors = %+v", existing.Authors)
	}
	if len(existing.ExternalReferences) != 1 {
		t.Errorf("external refs = %+v", existing.ExternalReferences)
	}
	// Properties dedupe on name AND value: a second value for a name is kept.
	if len(existing.Properties) != 2 {
		t.Errorf("properties = %+v", existing.Properties)
	}
}

func TestMergeVulnerabilitiesDedupesByIDRefAndAffects(t *testing.T) {
	bom := &BOM{Vulnerabilities: []Vulnerability{
		{ID: "CVE-1", BOMRef: "r1", Affects: []Affect{{Ref: "pkg:a"}}},
	}}
	mergeVulnerabilities(bom, []Vulnerability{
		{ID: "CVE-1", BOMRef: "r1", Affects: []Affect{{Ref: "pkg:a"}}}, // same: dropped
		{ID: "CVE-1", BOMRef: "r1", Affects: []Affect{{Ref: "pkg:b"}}}, // other package: kept
		{ID: "CVE-2", BOMRef: "r2"},
		{ID: "CVE-2", BOMRef: "r2"}, // repeated within incoming: dropped
	})
	if len(bom.Vulnerabilities) != 3 {
		t.Fatalf("vulnerabilities = %+v", bom.Vulnerabilities)
	}
	if bom.Vulnerabilities[0].Affects[0].Ref != "pkg:a" || bom.Vulnerabilities[1].Affects[0].Ref != "pkg:b" || bom.Vulnerabilities[2].ID != "CVE-2" {
		t.Errorf("order or content changed: %+v", bom.Vulnerabilities)
	}
}

func TestAppendPropIfMissing(t *testing.T) {
	props := []Property{{Name: "a", Value: "1"}}
	props = appendPropIfMissing(props, "a", "1")
	if len(props) != 1 {
		t.Fatalf("an identical pair is not appended: %+v", props)
	}
	props = appendPropIfMissing(props, "a", "2")
	props = appendPropIfMissing(props, "b", "1")
	if len(props) != 3 || props[1].Value != "2" || props[2].Name != "b" {
		t.Errorf("props = %+v", props)
	}
}

func TestExportCompRefs(t *testing.T) {
	bom := &BOM{Components: []Component{
		{Name: "lodash", Version: "4.17.20", BOMRef: "pkg:npm/lodash@4.17.20"},
		{Name: "@babel/core", Version: "7.0.0", BOMRef: "pkg:npm/%40babel/core@7.0.0"},
	}}
	want := map[string]string{
		"lodash@4.17.20":    "pkg:npm/lodash@4.17.20",
		"@babel/core@7.0.0": "pkg:npm/%40babel/core@7.0.0",
	}
	if got := ExportCompRefs(bom); !reflect.DeepEqual(got, want) {
		t.Errorf("ExportCompRefs = %v", got)
	}
	if got := ExportCompRefs(&BOM{}); len(got) != 0 {
		t.Errorf("empty BOM: %v", got)
	}
}
