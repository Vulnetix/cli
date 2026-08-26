package cdx

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	cyclonedx "github.com/Vulnetix/vdb-cyclonedx"
)

// scancodeOpamDoc is the shape ScanCode produced for an opam manifest in the
// sca-manifest-fixtures repo: a component whose second external reference is the
// manifest's URL template, passed through without ever being expanded. The real
// artifact failed with
//
//	at '/components/10/externalReferences/1/url':
//	'{https://opam.ocaml.org/packages}/{name}' is not valid iri-reference
const scancodeOpamDoc = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.3",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "myapp",
      "version": "0.1.0",
      "purl": "pkg:opam/myapp@0.1.0",
      "externalReferences": [
        {"url": "https://github.com/ocaml/opam-repository/blob/master/packages/myapp/myapp.0.1.0/opam", "type": "bom"},
        {"url": "{https://opam.ocaml.org/packages}/{name}", "type": "website"}
      ]
    }
  ]
}`

// TestNormalizeThirdPartyCDX_DropsInvalidIRIThenValidates is the whole point of
// the normaliser: the document fails validation before, passes after, and the
// component survives with its one good reference.
func TestNormalizeThirdPartyCDX_DropsInvalidIRIThenValidates(t *testing.T) {
	raw := []byte(scancodeOpamDoc)

	if err := cyclonedx.ValidateCDX(raw); err == nil {
		t.Fatal("expected the unhealed ScanCode document to fail validation")
	}

	healed, notes := NormalizeThirdPartyCDX(raw)
	if len(notes) != 1 {
		t.Fatalf("notes = %v, want exactly one", notes)
	}
	if !strings.Contains(notes[0], "opam.ocaml.org") || !strings.Contains(notes[0], "iri-reference") {
		t.Errorf("note should name the offending url and why it went: %q", notes[0])
	}

	if err := cyclonedx.ValidateCDX(healed); err != nil {
		t.Fatalf("healed document should validate, got: %v", err)
	}

	bom, err := cyclonedx.ParseCDX(healed)
	if err != nil {
		t.Fatalf("ParseCDX on healed document: %v", err)
	}
	if len(bom.Components) != 1 || bom.Components[0].Purl != "pkg:opam/myapp@0.1.0" {
		t.Fatalf("the component itself must survive the drop, got %+v", bom.Components)
	}

	// The good reference stays; only the bogus one goes.
	var doc struct {
		Components []struct {
			ExternalReferences []struct {
				URL string `json:"url"`
			} `json:"externalReferences"`
		} `json:"components"`
	}
	if err := json.Unmarshal(healed, &doc); err != nil {
		t.Fatal(err)
	}
	refs := doc.Components[0].ExternalReferences
	if len(refs) != 1 || !strings.HasPrefix(refs[0].URL, "https://github.com/ocaml/") {
		t.Errorf("externalReferences = %+v, want only the valid github url", refs)
	}
}

// TestNormalizeThirdPartyCDX_DedupesDependsOn covers the Trivy 1.6 failure:
// dependsOn is typed with uniqueItems, and Trivy listed one ref twice.
func TestNormalizeThirdPartyCDX_DedupesDependsOn(t *testing.T) {
	raw := []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "dependencies": [
    {"ref": "a", "dependsOn": ["b", "b", "c"]}
  ]
}`)

	if err := cyclonedx.ValidateCDX(raw); err == nil {
		t.Fatal("expected the duplicated dependsOn document to fail validation")
	}

	healed, notes := NormalizeThirdPartyCDX(raw)
	if len(notes) != 1 || !strings.Contains(notes[0], "duplicate") {
		t.Fatalf("notes = %v, want one note about duplicates", notes)
	}
	if err := cyclonedx.ValidateCDX(healed); err != nil {
		t.Fatalf("healed document should validate, got: %v", err)
	}

	var doc struct {
		Dependencies []struct {
			DependsOn []string `json:"dependsOn"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(healed, &doc); err != nil {
		t.Fatal(err)
	}
	got := doc.Dependencies[0].DependsOn
	if len(got) != 2 || got[0] != "b" || got[1] != "c" {
		t.Errorf("dependsOn = %v, want [b c] in first-seen order", got)
	}
}

// TestNormalizeThirdPartyCDX_ValidDocumentUntouched locks in that a clean
// document is returned byte-for-byte, so healing cannot churn an upload.
func TestNormalizeThirdPartyCDX_ValidDocumentUntouched(t *testing.T) {
	raw := []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {"component": {"type": "application", "name": "app", "version": "1.0.0"}},
  "components": [
    {
      "type": "library",
      "name": "left-pad",
      "version": "1.3.0",
      "bom-ref": "pkg:npm/left-pad@1.3.0",
      "purl": "pkg:npm/left-pad@1.3.0",
      "externalReferences": [
        {"url": "https://www.npmjs.com/package/left-pad", "type": "website"},
        {"url": "./relative/path", "type": "other"},
        {"url": "http://[::1]:8080/local", "type": "other"}
      ]
    }
  ],
  "dependencies": [{"ref": "pkg:npm/left-pad@1.3.0", "dependsOn": []}]
}`)

	if err := cyclonedx.ValidateCDX(raw); err != nil {
		t.Fatalf("fixture must be valid to start with, got: %v", err)
	}

	healed, notes := NormalizeThirdPartyCDX(raw)
	if len(notes) != 0 {
		t.Errorf("a valid document should produce no notes, got %v", notes)
	}
	if !bytes.Equal(healed, raw) {
		t.Errorf("a valid document should come back byte-for-byte:\n got %s\nwant %s", healed, raw)
	}
}

// TestNormalizeThirdPartyCDX_HealsNestedAndRootReferences checks the walk is
// keyed on the JSON key rather than a fixed path, since externalReferences also
// appears on the document root, on metadata.component and on nested components.
func TestNormalizeThirdPartyCDX_HealsNestedAndRootReferences(t *testing.T) {
	raw := []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "externalReferences": [{"url": "{https://example.com}/{name}", "type": "website"}],
  "metadata": {
    "component": {
      "type": "application", "name": "app", "version": "1.0.0",
      "externalReferences": [{"url": "back\\slash", "type": "other"}]
    }
  },
  "components": [
    {
      "type": "library", "name": "outer", "version": "1.0.0",
      "components": [
        {
          "type": "library", "name": "inner", "version": "1.0.0",
          "externalReferences": [
            {"url": "https://ok.example.com/", "type": "website"},
            {"url": "{https://opam.ocaml.org/packages}/{name}", "type": "website"}
          ]
        }
      ]
    }
  ]
}`)

	healed, notes := NormalizeThirdPartyCDX(raw)
	if len(notes) != 3 {
		t.Fatalf("notes = %v, want three (root, metadata.component, nested component)", notes)
	}
	if err := cyclonedx.ValidateCDX(healed); err != nil {
		t.Fatalf("healed document should validate, got: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(healed, &doc); err != nil {
		t.Fatal(err)
	}
	// An array emptied by the drop is removed rather than left as [].
	if _, present := doc["externalReferences"]; present {
		t.Error("root externalReferences emptied by the drop should be removed, not left bare")
	}
}

func TestValidIRIReference(t *testing.T) {
	for _, tc := range []struct {
		url  string
		want bool
	}{
		{"https://example.com/a/b", true},
		{"./relative/path", true},
		{"", true},
		{"urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", true},
		{"http://[::1]:8080/x", true},
		{"{https://opam.ocaml.org/packages}/{name}", false},
		{"back\\slash", false},
		{"http://exa mple.com", false},
	} {
		if got := validIRIReference(tc.url); got != tc.want {
			t.Errorf("validIRIReference(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}
