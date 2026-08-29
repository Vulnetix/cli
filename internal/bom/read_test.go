package bom

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/vulnetix/cli/v3/internal/cdx"
)

func loadFixture(t *testing.T, name string) *Document {
	t.Helper()
	doc, err := Load(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("Load(%s): %v", name, err)
	}
	return doc
}

func TestDetect(t *testing.T) {
	tests := []struct {
		name      string
		file      string
		format    Format
		spec      string
		envelope  Envelope
		supported bool
	}{
		{"spdx 2.3", "syft.spdx.json", FormatSPDX, "SPDX-2.3", EnvelopeNone, true},
		{"cyclonedx 1.6", "before.cdx.json", FormatCycloneDX, "1.6", EnvelopeNone, true},
		{"in-toto wrapped spdx", "buildkit.intoto.json", FormatSPDX, "SPDX-2.3", EnvelopeInToto, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", tt.file))
			if err != nil {
				t.Fatal(err)
			}
			got := Detect(data)
			if got.Format != tt.format {
				t.Errorf("Format = %q, want %q", got.Format, tt.format)
			}
			if got.SpecVersion != tt.spec {
				t.Errorf("SpecVersion = %q, want %q", got.SpecVersion, tt.spec)
			}
			if got.Envelope != tt.envelope {
				t.Errorf("Envelope = %q, want %q", got.Envelope, tt.envelope)
			}
			if got.Supported != tt.supported {
				t.Errorf("Supported = %v, want %v", got.Supported, tt.supported)
			}
		})
	}
}

// TestDetectUnwrapsDSSE covers the shape `cosign attest` and `syft attest`
// produce: an in-toto Statement base64'd inside a DSSE envelope. Sniffing the
// top level of one of these finds neither bomFormat nor spdxVersion, so without
// unwrapping every signed container SBOM would be unreadable.
func TestDetectUnwrapsDSSE(t *testing.T) {
	inner, err := os.ReadFile(filepath.Join("testdata", "buildkit.intoto.json"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(inner),
		"signatures":  []map[string]string{{"keyid": "", "sig": "ZmFrZQ=="}},
	})
	if err != nil {
		t.Fatal(err)
	}

	got := Detect(envelope)
	if got.Envelope != EnvelopeDSSE {
		t.Fatalf("Envelope = %q, want %q", got.Envelope, EnvelopeDSSE)
	}
	if got.Format != FormatSPDX || !got.Supported {
		t.Fatalf("Format = %q supported = %v, want spdx/true", got.Format, got.Supported)
	}

	doc, err := LoadBytes(envelope, "attestation.intoto.jsonl")
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if len(doc.BOM.Components) == 0 {
		t.Error("expected components from the unwrapped payload")
	}
	// The digest must cover the bytes the user actually has on disk — the
	// envelope — not the payload that fell out of it.
	if doc.Source.Digest == "" {
		t.Error("expected a source digest")
	}
}

func TestDetectRejectsNonSBOM(t *testing.T) {
	for _, input := range []string{
		`{"hello":"world"}`,
		`{"spdxVersion":"SPDX-3.0","SPDXID":"SPDXRef-DOCUMENT"}`,
		`not json at all`,
	} {
		if _, err := LoadBytes([]byte(input), ""); err == nil {
			t.Errorf("LoadBytes(%q) = nil error, want an error", input)
		}
	}
}

// TestSPDXRoundTrip is the parity lock for the reader: an SPDX document must
// survive normalisation into the CycloneDX model with its purls, licences,
// checksums and graph edges intact. Losing any of them would silently degrade
// every downstream consumer — diff, licence evaluation, VDB lookup — for SPDX
// input only, which is exactly the kind of asymmetry the canonical model exists
// to prevent.
func TestSPDXRoundTrip(t *testing.T) {
	doc := loadFixture(t, "syft.spdx.json")

	if doc.Source.Format != FormatSPDX || doc.Source.SpecVersion != "SPDX-2.3" {
		t.Fatalf("source = %v", doc.Source)
	}
	if got := doc.Name(); got != "payment-service" {
		t.Errorf("subject name = %q, want payment-service", got)
	}
	// The subject is lifted into metadata.component and must not also remain in
	// the component list beside its own dependencies.
	if len(doc.BOM.Components) != 3 {
		t.Fatalf("components = %d, want 3", len(doc.BOM.Components))
	}

	byName := map[string]*cdx.Component{}
	for i := range doc.BOM.Components {
		byName[doc.BOM.Components[i].Name] = &doc.BOM.Components[i]
	}

	lodash := byName["lodash"]
	if lodash == nil {
		t.Fatal("lodash missing")
	}
	if lodash.Purl != "pkg:npm/lodash@4.17.20" {
		t.Errorf("lodash purl = %q", lodash.Purl)
	}
	if lodash.BOMRef != lodash.Purl {
		t.Errorf("bom-ref = %q, want it to equal the purl", lodash.BOMRef)
	}
	if len(lodash.Licenses) != 1 || lodash.Licenses[0].License == nil || lodash.Licenses[0].License.ID != "MIT" {
		t.Errorf("lodash licenses = %+v, want a single MIT id", lodash.Licenses)
	}
	if len(lodash.Hashes) != 1 || lodash.Hashes[0].Alg != "SHA-256" {
		t.Errorf("lodash hashes = %+v, want one SHA-256", lodash.Hashes)
	}
	if !hasProperty(lodash, "vulnetix:spdx/supplier") {
		t.Error("lodash lost its supplier")
	}
	if !hasProperty(lodash, "vulnetix:sbom/ecosystem") {
		t.Error("lodash lost its ecosystem")
	}

	// A compound expression must stay one expression. Splitting "MIT OR
	// Apache-2.0" into two licence entries would assert the package is under
	// both, which is the opposite of what it says.
	dual := byName["dual-licensed-lib"]
	if dual == nil {
		t.Fatal("dual-licensed-lib missing")
	}
	if len(dual.Licenses) != 1 || dual.Licenses[0].Expression != "MIT OR Apache-2.0" {
		t.Errorf("dual licenses = %+v, want one expression", dual.Licenses)
	}

	// Source provenance survives normalisation.
	props := map[string]string{}
	for _, p := range doc.BOM.Metadata.Properties {
		props[p.Name] = p.Value
	}
	if props[PropSourceFormat] != "spdx" {
		t.Errorf("%s = %q", PropSourceFormat, props[PropSourceFormat])
	}
	if props[PropSourceDigest] == "" {
		t.Errorf("%s is empty", PropSourceDigest)
	}
}

// TestSPDXInverseRelationships covers DEPENDENCY_OF, which Syft emits and which
// a forward-only reader would silently drop — producing an empty graph for a
// document that fully describes one.
func TestSPDXInverseRelationships(t *testing.T) {
	doc := loadFixture(t, "syft.spdx.json")

	edges := map[string][]string{}
	for _, d := range doc.BOM.Dependencies {
		edges[d.Ref] = d.DependsOn
	}

	root := doc.BOM.Metadata.Component.BOMRef
	deps := edges[root]
	if len(deps) != 2 {
		t.Fatalf("root deps = %v, want 2 (one DEPENDS_ON, one flipped DEPENDENCY_OF)", deps)
	}
	want := map[string]bool{
		"pkg:npm/lodash@4.17.20":                            true,
		"pkg:golang/github.com/hashicorp/golang-lru@v0.5.4": true,
	}
	for _, d := range deps {
		if !want[d] {
			t.Errorf("unexpected root dependency %q", d)
		}
	}
}

func TestInTotoWrappedSPDX(t *testing.T) {
	doc := loadFixture(t, "buildkit.intoto.json")

	if doc.Source.Envelope != EnvelopeInToto {
		t.Errorf("envelope = %q, want in-toto", doc.Source.Envelope)
	}
	if doc.Source.PredicateType != "https://spdx.dev/Document" {
		t.Errorf("predicateType = %q", doc.Source.PredicateType)
	}
	if doc.BOM.Metadata.Component == nil || doc.BOM.Metadata.Component.Type != "container" {
		t.Errorf("subject = %+v, want a container component", doc.BOM.Metadata.Component)
	}
	if len(doc.BOM.Components) != 1 || doc.BOM.Components[0].Name != "openssl" {
		t.Errorf("components = %+v, want just openssl", doc.BOM.Components)
	}
	// CONTAINS is a containment relationship and must become a graph edge.
	if len(doc.BOM.Dependencies) != 1 {
		t.Errorf("dependencies = %+v, want one edge from the image", doc.BOM.Dependencies)
	}
}

// TestEnsureBOMRefs covers legal CycloneDX whose components carry purls but no
// bom-refs. The dependency graph addresses components by ref, so leaving them
// empty would produce a graph resolving to nothing.
func TestEnsureBOMRefs(t *testing.T) {
	input := `{
	  "bomFormat":"CycloneDX","specVersion":"1.5","version":1,
	  "components":[
	    {"type":"library","name":"a","version":"1.0.0","purl":"pkg:npm/a@1.0.0"},
	    {"type":"library","name":"b","version":"2.0.0"},
	    {"type":"library","name":"b","version":"2.0.0"}
	  ]
	}`
	doc, err := LoadBytes([]byte(input), "")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range doc.BOM.Components {
		if c.BOMRef == "" {
			t.Fatalf("component %q has no bom-ref", c.Name)
		}
		if seen[c.BOMRef] {
			t.Fatalf("duplicate bom-ref %q", c.BOMRef)
		}
		seen[c.BOMRef] = true
	}
	if doc.BOM.Components[0].BOMRef != "pkg:npm/a@1.0.0" {
		t.Errorf("expected the purl to be preferred as the ref, got %q", doc.BOM.Components[0].BOMRef)
	}
}
