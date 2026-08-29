package bom

import "testing"

func changeFor(d *Diff, name string, kind ChangeKind) *ComponentChange {
	for i := range d.Components {
		if d.Components[i].Name == name && d.Components[i].Kind == kind {
			return &d.Components[i]
		}
	}
	return nil
}

func TestCompareDocuments(t *testing.T) {
	from := loadFixture(t, "before.cdx.json")
	to := loadFixture(t, "after.cdx.json")
	d := CompareDocuments(from, to)

	if d.Identical {
		t.Fatal("distinct documents reported as identical")
	}

	// lodash 4.17.20 → 4.17.21 is one upgrade, not an add plus a remove. This
	// is what versionless-purl matching buys.
	up := changeFor(d, "lodash", ChangeUpgraded)
	if up == nil {
		t.Fatal("lodash upgrade not reported")
	}
	if up.FromVersion != "4.17.20" || up.ToVersion != "4.17.21" {
		t.Errorf("lodash versions = %s → %s", up.FromVersion, up.ToVersion)
	}

	// express 4.18.2 → 4.18.1 moved backwards. Reading that as an
	// undifferentiated change is the failure this ordering exists to prevent.
	down := changeFor(d, "express", ChangeDowngraded)
	if down == nil {
		t.Fatal("express downgrade not reported")
	}

	// express also changed licence, which is a separate finding from the
	// version movement — a reviewer needs to see both.
	lic := changeFor(d, "express", ChangeLicense)
	if lic == nil {
		t.Fatal("express licence change not reported")
	}
	if lic.FromLicense != "MIT" || lic.ToLicense != "Apache-2.0" {
		t.Errorf("express licence = %q → %q", lic.FromLicense, lic.ToLicense)
	}

	if changeFor(d, "chalk", ChangeAdded) == nil {
		t.Error("chalk addition not reported")
	}
	if changeFor(d, "left-pad", ChangeRemoved) == nil {
		t.Error("left-pad removal not reported")
	}

	s := d.Summary
	if s.Added != 1 || s.Removed != 1 || s.Upgraded != 1 || s.Downgraded != 1 || s.LicenseChanged != 1 {
		t.Errorf("summary = %+v", s)
	}
	if s.VulnsAdded != 1 || s.VulnsRemoved != 1 {
		t.Errorf("vuln summary = +%d -%d, want +1 -1", s.VulnsAdded, s.VulnsRemoved)
	}
	if s.FromComponents != 3 || s.ToComponents != 3 {
		t.Errorf("component counts = %d → %d", s.FromComponents, s.ToComponents)
	}
}

// TestDiffDirectness pins that directness is null, not false, when the document
// has no graph to answer from. Rendering an unmeasurable fact as "transitive"
// would be a confident wrong answer.
func TestDiffDirectness(t *testing.T) {
	from := loadFixture(t, "before.cdx.json")
	to := loadFixture(t, "after.cdx.json")
	d := CompareDocuments(from, to)

	added := changeFor(d, "chalk", ChangeAdded)
	if added == nil {
		t.Fatal("chalk addition not reported")
	}
	if added.Direct == nil || !*added.Direct {
		t.Errorf("chalk Direct = %v, want a direct dependency of the root", added.Direct)
	}

	noGraph := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
	  "components":[{"type":"library","name":"x","version":"1.0.0","purl":"pkg:npm/x@1.0.0"}]}`
	a, err := LoadBytes([]byte(noGraph), "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadBytes([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`), "")
	if err != nil {
		t.Fatal(err)
	}
	gd := CompareDocuments(a, b)
	if len(gd.Components) != 1 {
		t.Fatalf("changes = %+v", gd.Components)
	}
	if gd.Components[0].Direct != nil {
		t.Errorf("Direct = %v, want nil when there is no dependency graph", *gd.Components[0].Direct)
	}
}

// TestDiffIdenticalDigest checks that the same bytes twice says so plainly,
// rather than leaving the reader to interpret an empty change list.
func TestDiffIdenticalDigest(t *testing.T) {
	a := loadFixture(t, "before.cdx.json")
	b := loadFixture(t, "before.cdx.json")
	d := CompareDocuments(a, b)
	if !d.Identical {
		t.Error("identical inputs not reported as identical")
	}
	if d.Summary.Total() != 0 {
		t.Errorf("identical inputs produced %d changes", d.Summary.Total())
	}
}

// TestDiffAcrossFormats is the point of the canonical model: an SPDX document
// and a CycloneDX document describing the same tree must be comparable.
func TestDiffAcrossFormats(t *testing.T) {
	spdx := loadFixture(t, "syft.spdx.json")
	cdxDoc := loadFixture(t, "before.cdx.json")
	d := CompareDocuments(spdx, cdxDoc)

	// lodash is at 4.17.20 on both sides, so it must match rather than appear
	// as a removal plus an addition.
	for _, c := range d.Components {
		if c.Name == "lodash" && (c.Kind == ChangeAdded || c.Kind == ChangeRemoved) {
			t.Errorf("lodash reported as %s across formats; purl matching failed", c.Kind)
		}
	}
}

func TestVersionChangeKind(t *testing.T) {
	tests := []struct {
		from, to string
		want     ChangeKind
	}{
		{"1.2.3", "1.2.4", ChangeUpgraded},
		{"1.2.10", "1.2.9", ChangeDowngraded},
		{"1.2.0", "v1.2.0", ChangeVersionChanged},
		{"abc123", "def456", ChangeVersionChanged},
	}
	for _, tt := range tests {
		if got := versionChangeKind(tt.from, tt.to); got != tt.want {
			t.Errorf("versionChangeKind(%q, %q) = %q, want %q", tt.from, tt.to, got, tt.want)
		}
	}
}

func TestPurlWithoutVersion(t *testing.T) {
	tests := map[string]string{
		"pkg:npm/lodash@4.17.21": "pkg:npm/lodash",
		// Scoped npm packages are routinely emitted with a raw '@' in the
		// namespace. Splitting on the first one collapses every scoped package
		// to "pkg:npm/", which would pair unrelated components in a diff.
		"pkg:npm/@scope/pkg@1.0.0":           "pkg:npm/@scope/pkg",
		"pkg:npm/%40scope/pkg@1.0.0":         "pkg:npm/%40scope/pkg",
		"pkg:golang/example.com/m@v1.2.3":    "pkg:golang/example.com/m",
		"pkg:deb/debian/curl@7.1?arch=amd64": "pkg:deb/debian/curl",
		"pkg:npm/lodash":                     "pkg:npm/lodash",
		"pkg:npm/@scope/pkg":                 "pkg:npm/@scope/pkg",
		"":                                   "",
	}
	for in, want := range tests {
		if got := purlWithoutVersion(in); got != want {
			t.Errorf("purlWithoutVersion(%q) = %q, want %q", in, got, want)
		}
	}
}
