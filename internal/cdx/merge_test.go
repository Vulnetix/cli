package cdx

import (
	"testing"
)

func TestMergeUpstream_NilLocal_FallsBackToEmptyBOM(t *testing.T) {
	bom, err := MergeUpstream(nil, map[string]any{
		"components": []any{
			map[string]any{
				"type":    "library",
				"name":    "lodash",
				"version": "4.17.20",
				"purl":    "pkg:npm/lodash@4.17.20",
				"bom-ref": "pkg:npm/lodash@4.17.20",
			},
		},
	})
	if err != nil {
		t.Fatalf("merge failed: %v", err)
	}
	if len(bom.Components) != 1 {
		t.Fatalf("expected upstream component to be appended; got %d", len(bom.Components))
	}
	if bom.Components[0].Purl != "pkg:npm/lodash@4.17.20" {
		t.Errorf("purl not preserved: %v", bom.Components[0].Purl)
	}
}

func TestMergeUpstream_RewritesAffectsRef(t *testing.T) {
	local := &BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
		Components: []Component{
			{
				Type:    "library",
				BOMRef:  "local-lodash",
				Name:    "lodash",
				Version: "4.17.20",
				Purl:    "pkg:npm/lodash@4.17.20",
			},
		},
	}

	upstream := map[string]any{
		"components": []any{
			map[string]any{
				"bom-ref": "upstream-lodash",
				"purl":    "pkg:npm/lodash@4.17.20",
				"name":    "lodash",
				"version": "4.17.20",
				"group":   "",
			},
		},
		"vulnerabilities": []any{
			map[string]any{
				"id":          "CVE-2021-23337",
				"description": "Prototype Pollution",
				"source":      map[string]any{"name": "nvd"},
				"ratings": []any{
					map[string]any{
						"score":    7.2,
						"severity": "high",
						"method":   "CVSSv3",
						"source":   map[string]any{"name": "cvss"},
					},
				},
				"affects": []any{
					map[string]any{"ref": "upstream-lodash"},
				},
			},
		},
	}

	bom, err := MergeUpstream(local, upstream)
	if err != nil {
		t.Fatalf("merge failed: %v", err)
	}

	if len(bom.Components) != 1 {
		t.Fatalf("local component should be deduped against upstream; got %d", len(bom.Components))
	}
	if len(bom.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability after merge; got %d", len(bom.Vulnerabilities))
	}
	v := bom.Vulnerabilities[0]
	if v.ID != "CVE-2021-23337" {
		t.Errorf("vuln id not preserved: %v", v.ID)
	}
	if len(v.Affects) != 1 || v.Affects[0].Ref != "local-lodash" {
		t.Errorf("affects.ref not rewritten to local bom-ref; got %+v", v.Affects)
	}
	if len(v.Ratings) != 1 || v.Ratings[0].Score != 7.2 {
		t.Errorf("rating not preserved: %+v", v.Ratings)
	}
}

func TestMergeUpstream_PreservesLocalOnlyComponents(t *testing.T) {
	local := &BOM{
		Components: []Component{
			{Type: "library", BOMRef: "local-only", Name: "private-pkg", Version: "0.1.0"},
		},
	}
	upstream := map[string]any{
		"components": []any{
			map[string]any{"bom-ref": "u1", "name": "other", "version": "1.0.0", "purl": "pkg:npm/other@1.0.0"},
		},
	}
	bom, err := MergeUpstream(local, upstream)
	if err != nil {
		t.Fatalf("merge failed: %v", err)
	}
	if len(bom.Components) != 2 {
		t.Fatalf("expected local + upstream components; got %d", len(bom.Components))
	}
	foundLocal := false
	for _, c := range bom.Components {
		if c.Name == "private-pkg" {
			foundLocal = true
		}
	}
	if !foundLocal {
		t.Error("local-only component must be preserved")
	}
}

func TestParseUpstreamFromJSON(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`)
	doc, err := ParseUpstreamFromJSON(raw)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if doc["bomFormat"] != "CycloneDX" {
		t.Errorf("decode wrong: %v", doc)
	}
}
