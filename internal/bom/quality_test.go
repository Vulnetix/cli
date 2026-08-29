package bom

import (
	"strings"
	"testing"
)

func fieldByName(fields []FieldReport, name string) *FieldReport {
	for i := range fields {
		if fields[i].Field == name {
			return &fields[i]
		}
	}
	return nil
}

func TestQualityReportsPerField(t *testing.T) {
	doc := loadFixture(t, "before.cdx.json")
	rep := Quality(doc)

	if rep.ComponentCount != 3 {
		t.Fatalf("ComponentCount = %d, want 3", rep.ComponentCount)
	}

	// Every component in this fixture has a name, a version, an identifier and
	// a licence; none has a checksum or a supplier. A single score would hide
	// exactly that distinction, which is why the breakdown is the output.
	for _, complete := range []string{"component.name", "component.version", "component.identifier", "component.license"} {
		f := fieldByName(rep.Components, complete)
		if f == nil {
			t.Fatalf("missing field %s", complete)
		}
		if !f.Complete() {
			t.Errorf("%s = %d/%d, want complete", complete, f.Present, f.Total)
		}
	}
	if f := fieldByName(rep.Components, "component.hash"); f == nil || f.Present != 0 {
		t.Errorf("component.hash = %+v, want 0 present", f)
	}

	if f := fieldByName(rep.Document, "document.dependencies"); f == nil || !f.Complete() {
		t.Errorf("document.dependencies = %+v, want complete", f)
	}
	if rep.Score <= 0 || rep.Score > 100 {
		t.Errorf("Score = %d, want 1..100", rep.Score)
	}
}

// TestQualityNamesOffenders pins that a shortfall says which components are
// missing the field. A bare count tells a user their SBOM is deficient; the
// names tell them where to look.
func TestQualityNamesOffenders(t *testing.T) {
	input := `{
	  "bomFormat":"CycloneDX","specVersion":"1.6","version":1,
	  "components":[
	    {"type":"library","name":"alpha","purl":"pkg:npm/alpha"},
	    {"type":"library","name":"beta","version":"1.0.0","purl":"pkg:npm/beta@1.0.0"}
	  ]
	}`
	doc, err := LoadBytes([]byte(input), "")
	if err != nil {
		t.Fatal(err)
	}
	rep := Quality(doc)

	f := fieldByName(rep.Components, "component.version")
	if f == nil {
		t.Fatal("component.version missing")
	}
	if f.Present != 1 || f.Total != 2 {
		t.Fatalf("component.version = %d/%d, want 1/2", f.Present, f.Total)
	}
	if f.Detail == "" {
		t.Fatal("expected a detail naming the offending component")
	}
	if want := "pkg:npm/alpha"; !strings.Contains(f.Detail, want) {
		t.Errorf("Detail = %q, want it to name %q", f.Detail, want)
	}
}

func TestQualityIncompleteOrdering(t *testing.T) {
	doc := loadFixture(t, "before.cdx.json")
	inc := Quality(doc).Incomplete()
	if len(inc) == 0 {
		t.Fatal("expected some incomplete fields")
	}
	for i := 1; i < len(inc); i++ {
		if inc[i-1].Ratio() > inc[i].Ratio() {
			t.Errorf("Incomplete() not ordered worst-first at %d: %v > %v",
				i, inc[i-1].Ratio(), inc[i].Ratio())
		}
	}
}

func TestQualityNilSafe(t *testing.T) {
	if rep := Quality(nil); rep == nil || rep.Score != 0 {
		t.Errorf("Quality(nil) = %+v, want a zero report", rep)
	}
}
