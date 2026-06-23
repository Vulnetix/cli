package cyclonedx

import (
	"reflect"
	"testing"
)

// bom with graph: root → a → b (transitive), root → c (direct).
func graphBOM() *CDXBom {
	return &CDXBom{
		SpecVersion: "1.6",
		Metadata: CDXMetadata{Component: &CDXComponent{
			Type: "application", BomRef: "root", Name: "app", Version: "1.0.0",
		}},
		Components: []CDXComponent{
			{BomRef: "a", Name: "a", Version: "1.0.0", Purl: "pkg:npm/a@1.0.0"},
			{BomRef: "b", Name: "b", Version: "2.0.0", Purl: "pkg:npm/b@2.0.0"},
			{BomRef: "c", Name: "c", Version: "3.0.0", Purl: "pkg:npm/c@3.0.0"},
		},
		Dependencies: []CDXDependency{
			{Ref: "root", DependsOn: []string{"a", "c"}},
			{Ref: "a", DependsOn: []string{"b"}},
		},
	}
}

func TestShortestDepPath(t *testing.T) {
	bom := graphBOM()

	// transitive: root excluded, chain a → b
	if got := ShortestDepPath(bom, "b"); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("path to b: expected [a b], got %v", got)
	}
	// direct child of root
	if got := ShortestDepPath(bom, "c"); !reflect.DeepEqual(got, []string{"c"}) {
		t.Fatalf("path to c: expected [c], got %v", got)
	}
	// unreachable ref → nil
	if got := ShortestDepPath(bom, "missing"); got != nil {
		t.Fatalf("path to missing: expected nil, got %v", got)
	}
	// no root component → nil
	if got := ShortestDepPath(&CDXBom{}, "b"); got != nil {
		t.Fatalf("no-root path: expected nil, got %v", got)
	}
}

func TestBuildIntroducedViaFromBOM(t *testing.T) {
	bom := graphBOM()
	compByRef := map[string]*CDXComponent{}
	for i := range bom.Components {
		compByRef[bom.Components[i].BomRef] = &bom.Components[i]
	}

	rows := BuildIntroducedViaFromBOM(bom, "urn:uuid:x", "b", "npm", compByRef)
	if len(rows) != 1 {
		t.Fatalf("expected 1 introduced-via row, got %d", len(rows))
	}
	r := rows[0]
	if r.PathLength != 2 || r.PackageManager != "npm" || r.ManifestFile != "sbom" {
		t.Fatalf("row metadata mismatch: %+v", r)
	}
	if r.DependencyPath != "a@1.0.0 > b@2.0.0" {
		t.Fatalf("dependency path mismatch: %q", r.DependencyPath)
	}
	wantKeys := []string{"urn:uuid:x:a:1.0.0", "urn:uuid:x:b:2.0.0"}
	if !reflect.DeepEqual(r.DependencyKeys, wantKeys) {
		t.Fatalf("dependency keys mismatch: %v", r.DependencyKeys)
	}

	// unknown target → nil
	if rows := BuildIntroducedViaFromBOM(bom, "x", "nope", "npm", compByRef); rows != nil {
		t.Fatalf("unknown target should yield nil, got %v", rows)
	}
}

func TestComponentKeyAndRegistry(t *testing.T) {
	c := &CDXComponent{Name: "lodash", Version: "4.17.21"}
	if got := ComponentKey("cdx1", c); got != "cdx1:lodash:4.17.21" {
		t.Fatalf("ComponentKey: got %q", got)
	}
	if got := RegistryURLForEcosystem("npm"); got != "https://registry.npmjs.org" {
		t.Fatalf("RegistryURLForEcosystem npm: got %q", got)
	}
	if got := RegistryURLForEcosystem("unknown-eco"); got != "" {
		t.Fatalf("RegistryURLForEcosystem unknown: got %q", got)
	}
	if got := AdvisoryURL("CVE-2022-0001"); got != "https://nvd.nist.gov/vuln/detail/CVE-2022-0001" {
		t.Fatalf("AdvisoryURL: got %q", got)
	}
}
