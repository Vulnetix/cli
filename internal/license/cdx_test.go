package license

import (
	"strings"
	"testing"

	"github.com/vulnetix/cli/v3/internal/cdx"
)

// TestPopulateLicenses_InvalidSPDXIDStillValidates is the end-to-end regression
// guard for the canonical .vulnetix/sbom.cdx.json write. Before the fix, an
// unrecognised SPDX id from the license detector (registry strings like "BSD",
// proprietary names, typos) was emitted as the enum-constrained CycloneDX
// license.id, so MarshalValidatedJSON — the write-time schema guard — rejected
// the document and the canonical SBOM write failed. Routing such values to the
// free-text license.name via CanonicalSPDXID must keep the BOM valid while a
// genuine SPDX id is still emitted (canonically) as license.id.
func TestPopulateLicenses_InvalidSPDXIDStillValidates(t *testing.T) {
	bom := &cdx.BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.7",
		SerialNumber: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
		Version:      1,
		Components: []cdx.Component{
			{Type: "library", BOMRef: "pkg:npm/good@1.0.0", Name: "good", Version: "1.0.0"},
			{Type: "library", BOMRef: "pkg:npm/bad@1.0.0", Name: "bad", Version: "1.0.0"},
		},
	}
	licenseMap := map[string]string{
		"good@1.0.0": "mit",           // recognised → canonical license.id "MIT"
		"bad@1.0.0":  "Public Domain", // not an SPDX id → must demote to license.name
	}

	cdx.PopulateLicenses(bom, licenseMap, CanonicalSPDXID)

	data, err := bom.MarshalValidatedJSON()
	if err != nil {
		t.Fatalf("canonical SBOM failed schema validation after license populate: %v", err)
	}
	js := string(data)
	if !strings.Contains(js, `"id": "MIT"`) {
		t.Errorf("recognised license should be emitted as canonical license.id=MIT:\n%s", js)
	}
	if !strings.Contains(js, `"name": "Public Domain"`) {
		t.Errorf("unrecognised license should be emitted as license.name:\n%s", js)
	}
	if strings.Contains(js, `"id": "Public Domain"`) {
		t.Errorf("unrecognised license must not appear as enum-constrained license.id:\n%s", js)
	}
}
