package cdx

import (
	"encoding/json"
	"strings"
	"testing"

	cyclonedx "github.com/Vulnetix/vdb-cyclonedx"
)

func mustOverlay(t *testing.T, name string) Overlay {
	t.Helper()
	ov, err := LoadOverlay("testdata/overlay/" + name)
	if err != nil {
		t.Fatalf("LoadOverlay(%s): %v", name, err)
	}
	return ov
}

// builtDoc is what a generator produces before any customisation: a 1.7
// document with a subject component, one package, a graph and a finding.
func builtDoc() *BOM {
	doc := cyclonedx.NewDocument("1.7")
	doc.Metadata.Component = &Component{Type: "application", BOMRef: "urn:project", Name: "repo", Version: "abc1234",
		Properties: []Property{{Name: "vulnetix:git/commit", Value: "abc1234"}}}
	doc.Components = []Component{{Type: "library", Name: "left-pad", Version: "1.3.0", Purl: "pkg:npm/left-pad@1.3.0", BOMRef: "pkg:npm/left-pad@1.3.0",
		Licenses: []LicenseChoice{{License: &LicenseData{ID: "MIT"}}}}}
	doc.Dependencies = []CDXDependency{{Ref: "urn:project", DependsOn: []string{"pkg:npm/left-pad@1.3.0"}}}
	doc.Vulnerabilities = []Vulnerability{{BOMRef: "vuln:CVE-2020-0001", ID: "CVE-2020-0001", Affects: []Affect{{Ref: "pkg:npm/left-pad@1.3.0"}}}}
	_, _ = cyclonedx.ApplyAuthorship(doc, Authoring(cyclonedx.ToolCDX, nil, PhaseBuild))
	return doc
}

func TestLoadOverlayRejectsWhatItMust(t *testing.T) {
	cases := map[string]string{
		"signed.cdx.json":   "/signature",
		"reserved.cdx.json": "/components/0/properties/0/name",
		"spdx.json":         "/bomFormat",
		"missing.json":      "no such file",
	}
	for name, want := range cases {
		_, err := LoadOverlay("testdata/overlay/" + name)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want error naming %q, got %v", name, want, err)
		}
	}
}

func TestApplyOverlayRejectsAnotherSpecVersion(t *testing.T) {
	doc := builtDoc()
	doc.SpecVersion = "1.6"
	err := ApplyOverlay(doc, mustOverlay(t, "full.cdx.json"))
	if err == nil || !strings.Contains(err.Error(), "/specVersion") {
		t.Fatalf("want a /specVersion error, got %v", err)
	}
}

func TestApplyOverlayMergesEveryMember(t *testing.T) {
	doc := builtDoc()
	ov := mustOverlay(t, "full.cdx.json")
	if err := ApplyOverlay(doc, ov); err != nil {
		t.Fatal(err)
	}

	// Identity members are ResolveAuthorship's; ApplyOverlay leaves them alone.
	if doc.Version != 1 || doc.Metadata.Manufacturer != nil || len(doc.Metadata.Authors) != 0 || doc.Metadata.Supplier != nil {
		t.Errorf("ApplyOverlay touched identity members: version=%d manufacturer=%v authors=%v supplier=%v",
			doc.Version, doc.Metadata.Manufacturer, doc.Metadata.Authors, doc.Metadata.Supplier)
	}
	if doc.Metadata.Timestamp == "1999-01-01T00:00:00Z" {
		t.Error("metadata.timestamp came from the overlay")
	}
	if tool := cyclonedx.AuthoringTool(doc); tool == nil || tool.Name != cyclonedx.ToolCDX {
		t.Errorf("metadata.tools changed: %+v", doc.Metadata.Tools)
	}

	// The subject component: scalars overlay-wins, bom-ref kept, arrays appended, properties upserted.
	c := doc.Metadata.Component
	if c.Name != "payment-service" || c.Version != "2.0.0" || c.BOMRef != "urn:project" {
		t.Errorf("metadata.component = %s@%s ref %s", c.Name, c.Version, c.BOMRef)
	}
	if c.Supplier == nil || c.Supplier.Name != "Acme Supplier" {
		t.Errorf("metadata.component.supplier = %v", c.Supplier)
	}
	if len(c.Licenses) != 1 || c.Licenses[0].License.ID != "Apache-2.0" {
		t.Errorf("metadata.component.licenses = %+v", c.Licenses)
	}
	if got := propValue(c.Properties, "vulnetix:git/commit"); got != "abc1234" {
		t.Errorf("derived property lost: %q", got)
	}
	if got := propValue(c.Properties, "acme:tier"); got != "1" {
		t.Errorf("overlay property missing: %q", got)
	}

	// Document licences and properties.
	if len(doc.Metadata.Licenses) != 1 || doc.Metadata.Licenses[0].License.ID != "CC0-1.0" {
		t.Errorf("metadata.licenses = %+v", doc.Metadata.Licenses)
	}
	if got := propValue(doc.Metadata.Properties, "acme:team"); got != "payments" {
		t.Errorf("metadata.properties acme:team = %q", got)
	}

	// Components: matched by purl gets the overlay's supplier and an appended licence; new one appended.
	if len(doc.Components) != 2 {
		t.Fatalf("components = %d, want 2", len(doc.Components))
	}
	lp := doc.Components[0]
	if lp.Supplier == nil || lp.Supplier.Name != "Left Pad Org" {
		t.Errorf("matched component supplier = %v", lp.Supplier)
	}
	if len(lp.Licenses) != 2 {
		t.Errorf("matched component licences = %+v, want MIT then WTFPL", lp.Licenses)
	}
	if doc.Components[1].Name != "extra-lib" {
		t.Errorf("appended component = %s", doc.Components[1].Name)
	}

	// Dependencies: union on urn:project.
	if len(doc.Dependencies) != 1 || len(doc.Dependencies[0].DependsOn) != 2 {
		t.Errorf("dependencies = %+v", doc.Dependencies)
	}

	// Vulnerabilities: the overlay's analysis replaces the finding's.
	if len(doc.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities = %d, want 1", len(doc.Vulnerabilities))
	}
	a := doc.Vulnerabilities[0].Analysis
	if a == nil || a.State != "not_affected" || a.Justification != "code_not_reachable" || a.Detail != "Never called" {
		t.Errorf("analysis = %+v", a)
	}
	if len(doc.Vulnerabilities[0].Affects) != 1 {
		t.Errorf("affects lost: %+v", doc.Vulnerabilities[0].Affects)
	}

	// Members this model does not interpret survive to the bytes.
	data, err := MarshalValidated(doc)
	if err != nil {
		t.Fatalf("MarshalValidated: %v", err)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	for _, member := range []string{"services", "compositions", "annotations", "externalReferences"} {
		if _, ok := out[member]; !ok {
			t.Errorf("%s missing from the marshalled document", member)
		}
	}
}

func TestLaterOverlayWins(t *testing.T) {
	doc := builtDoc()
	in := AuthoringInputs{Overlays: []Overlay{mustOverlay(t, "full.cdx.json"), mustOverlay(t, "later.cdx.json")}}
	if err := ApplyDocumentOverrides(doc, in); err != nil {
		t.Fatal(err)
	}
	if doc.Metadata.Component.Name != "later-name" {
		t.Errorf("component name = %q, want the later overlay's", doc.Metadata.Component.Name)
	}
	if got := propValue(doc.Metadata.Properties, "acme:team"); got != "platform" {
		t.Errorf("acme:team = %q, want the later overlay's", got)
	}
	var services []map[string]any
	if err := json.Unmarshal(doc.Extra["services"], &services); err != nil || len(services) != 1 || services[0]["name"] != "later-svc" {
		t.Errorf("services = %s, want replaced by the later overlay", doc.Extra["services"])
	}
}

func TestFlagsBeatOverlay(t *testing.T) {
	doc := builtDoc()
	in := AuthoringInputs{
		Overlays:   []Overlay{mustOverlay(t, "full.cdx.json")},
		Properties: []Property{{Name: "acme:team", Value: "from-flag"}},
		Licenses:   []LicenseChoice{{License: &LicenseData{ID: "MIT"}}},
		Component:  ComponentOverride{Name: "from-flag", Type: "framework", Group: "acme", Purl: "pkg:generic/acme/from-flag@1"},
	}
	if err := ApplyDocumentOverrides(doc, in); err != nil {
		t.Fatal(err)
	}
	if got := propValue(doc.Metadata.Properties, "acme:team"); got != "from-flag" {
		t.Errorf("acme:team = %q", got)
	}
	if len(doc.Metadata.Licenses) != 2 {
		t.Errorf("metadata.licenses = %+v, want the overlay's and the flag's", doc.Metadata.Licenses)
	}
	c := doc.Metadata.Component
	if c.Name != "from-flag" || c.Type != "framework" || c.Group != "acme" || c.Purl != "pkg:generic/acme/from-flag@1" || c.Version != "2.0.0" {
		t.Errorf("component = %+v", c)
	}
}

func TestMarshalValidatedListsEveryViolationWithAHint(t *testing.T) {
	doc := builtDoc()
	doc.Metadata.Authors = []OrganizationalContact{{Name: "ok"}}
	doc.Metadata.Component.Type = "not-a-type"
	doc.Extra = map[string]json.RawMessage{"services": json.RawMessage(`[{"endpoints": "not-an-array"}]`)}
	_, err := MarshalValidated(doc)
	if err == nil {
		t.Fatal("want violations")
	}
	msg := err.Error()
	for _, want := range []string{"/metadata/component/type", "--component-*", "/services/0", "from an overlay", "violation(s)"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error lacks %q:\n%s", want, msg)
		}
	}
}

func propValue(props []Property, name string) string {
	v, _ := cyclonedx.GetProperty(props, name)
	return v
}
