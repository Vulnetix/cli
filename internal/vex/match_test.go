package vex

import (
	"testing"
	"time"
)

func setOf(t *testing.T, names ...string) *Set {
	t.Helper()
	docs := make([]*Document, 0, len(names))
	for _, n := range names {
		docs = append(docs, loadDoc(t, n))
	}
	return NewSet(docs)
}

// TestMatchExactPurl is the baseline every VEX consumer gets right.
func TestMatchExactPurl(t *testing.T) {
	set := setOf(t, "vendor.openvex.json")
	m, ok := set.Match(Finding{
		VulnID: "CVE-2020-8203", Purl: "pkg:npm/lodash@4.17.20", Version: "4.17.20",
	})
	if !ok {
		t.Fatal("exact purl did not match")
	}
	if m.Basis != BasisExactPurl {
		t.Errorf("basis = %q, want exact-purl", m.Basis)
	}
	if !m.Suppresses() {
		t.Error("not_affected did not suppress")
	}
	if m.Explain == "" {
		t.Error("no explanation — a suppressed finding must say why")
	}
}

// TestMatchPurlAnyVersion is the case exact-equality matching silently drops: a
// statement naming a package with no version means every version of it.
func TestMatchPurlAnyVersion(t *testing.T) {
	set := setOf(t, "vendor.openvex.json")
	for _, version := range []string{"4.18.1", "4.18.2", "5.0.0"} {
		m, ok := set.Match(Finding{
			VulnID: "CVE-2024-9999", Purl: "pkg:npm/express@" + version, Version: version,
		})
		if !ok {
			t.Fatalf("unversioned product statement did not reach express@%s", version)
		}
		if m.Basis != BasisPurlAnyVersion {
			t.Errorf("basis = %q, want purl-any-version", m.Basis)
		}
		// affected is not a suppression. Treating it as one would be the exact
		// opposite of what the publisher said.
		if m.Suppresses() {
			t.Error("an `affected` statement suppressed a finding")
		}
	}
}

// TestMatchVersionRange is the other case exact equality drops: a statement
// scoping a range must reach every version inside it.
func TestMatchVersionRange(t *testing.T) {
	set := setOf(t, "vendor.openvex.json")

	m, ok := set.Match(Finding{
		VulnID: "CVE-2021-1111", Purl: "pkg:npm/left-pad@1.3.0", Version: "1.3.0",
	})
	if !ok {
		t.Fatal("a version inside the statement's range did not match")
	}
	if m.Basis != BasisPurlVersionRange {
		t.Errorf("basis = %q, want purl-version-range", m.Basis)
	}
	if !m.Suppresses() {
		t.Error("fixed did not suppress")
	}

	// Outside the range must not match. A range that matched everything would
	// be worse than no matching at all.
	if _, ok := set.Match(Finding{
		VulnID: "CVE-2021-1111", Purl: "pkg:npm/left-pad@2.5.0", Version: "2.5.0",
	}); ok {
		t.Error("a version outside the statement's range matched")
	}
}

// TestMatchByAlias covers a finding reported under a different identifier from
// the one the statement was written against.
func TestMatchByAlias(t *testing.T) {
	set := setOf(t, "vendor.openvex.json")
	if _, ok := set.Match(Finding{
		VulnID: "GHSA-aaaa-bbbb-cccc", Purl: "pkg:npm/left-pad@1.3.0", Version: "1.3.0",
	}); !ok {
		t.Error("a statement's alias did not match a finding reported under that alias")
	}
}

func TestMatchWrongPackageDoesNotMatch(t *testing.T) {
	set := setOf(t, "vendor.openvex.json")
	if _, ok := set.Match(Finding{
		VulnID: "CVE-2020-8203", Purl: "pkg:npm/underscore@1.13.6", Version: "1.13.6",
	}); ok {
		t.Error("a statement about lodash matched underscore")
	}
}

// TestMatchScopedNpmPackages pins that the versionless-purl key does not
// collapse every scoped package onto "pkg:npm/", which would make one
// statement suppress findings in unrelated packages.
func TestMatchScopedNpmPackages(t *testing.T) {
	doc, err := LoadBytes([]byte(`{
	  "@context":"https://openvex.dev/ns/v0.2.0","@id":"x","author":"a","version":1,
	  "statements":[{
	    "vulnerability":{"name":"CVE-1"},"status":"not_affected",
	    "justification":"component_not_present",
	    "products":[{"@id":"pkg:npm/@scope/alpha"}]
	  }]
	}`), "")
	if err != nil {
		t.Fatal(err)
	}
	set := NewSet([]*Document{doc})

	if _, ok := set.Match(Finding{VulnID: "CVE-1", Purl: "pkg:npm/@scope/alpha@1.0.0", Version: "1.0.0"}); !ok {
		t.Error("the statement did not reach its own scoped package")
	}
	if _, ok := set.Match(Finding{VulnID: "CVE-1", Purl: "pkg:npm/@scope/beta@1.0.0", Version: "1.0.0"}); ok {
		t.Error("a statement about @scope/alpha matched @scope/beta")
	}
}

// TestMatchSpecificityWins pins that a statement scoped to an exact version
// beats a broader one about the same package.
func TestMatchSpecificityWins(t *testing.T) {
	doc, err := LoadBytes([]byte(`{
	  "@context":"https://openvex.dev/ns/v0.2.0","@id":"x","author":"a","version":1,
	  "statements":[
	    {"vulnerability":{"name":"CVE-1"},"status":"affected",
	     "action_statement":"upgrade","products":[{"@id":"pkg:npm/foo"}]},
	    {"vulnerability":{"name":"CVE-1"},"status":"not_affected",
	     "justification":"component_not_present","products":[{"@id":"pkg:npm/foo@1.0.0"}]}
	  ]
	}`), "")
	if err != nil {
		t.Fatal(err)
	}
	set := NewSet([]*Document{doc})

	m, ok := set.Match(Finding{VulnID: "CVE-1", Purl: "pkg:npm/foo@1.0.0", Version: "1.0.0"})
	if !ok {
		t.Fatal("no match")
	}
	if m.Basis != BasisExactPurl || m.Status() != StatusNotAffected {
		t.Errorf("basis = %q status = %q; the version-specific statement should win",
			m.Basis, m.Status())
	}

	// A different version has only the broad statement to answer to.
	m2, ok := set.Match(Finding{VulnID: "CVE-1", Purl: "pkg:npm/foo@2.0.0", Version: "2.0.0"})
	if !ok {
		t.Fatal("no match for the broader statement")
	}
	if m2.Status() != StatusAffected {
		t.Errorf("status = %q, want the broad affected statement", m2.Status())
	}
}

// TestMatchNewerSupersedes pins that a later assertion about the same thing
// wins — VEX is a running claim, not an append-only log.
func TestMatchNewerSupersedes(t *testing.T) {
	older := Statement{
		VulnID: "CVE-1", Status: StatusUnderInvestigation,
		Products:  []Product{{Purl: "pkg:npm/foo@1.0.0"}},
		Timestamp: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
	}
	newer := Statement{
		VulnID: "CVE-1", Status: StatusNotAffected, Justification: "component_not_present",
		Products:  []Product{{Purl: "pkg:npm/foo@1.0.0"}},
		Timestamp: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
	}
	set := NewSet([]*Document{{Statements: []Statement{older, newer}}})

	m, ok := set.Match(Finding{VulnID: "CVE-1", Purl: "pkg:npm/foo@1.0.0", Version: "1.0.0"})
	if !ok {
		t.Fatal("no match")
	}
	if m.Status() != StatusNotAffected {
		t.Errorf("status = %q, want the June statement to supersede the March one", m.Status())
	}
}

func TestPurlHelpers(t *testing.T) {
	versionless := map[string]string{
		"pkg:npm/lodash@4.17.21":             "pkg:npm/lodash",
		"pkg:npm/@scope/pkg@1.0.0":           "pkg:npm/@scope/pkg",
		"pkg:deb/debian/curl@7.1?arch=amd64": "pkg:deb/debian/curl",
		"pkg:npm/lodash":                     "pkg:npm/lodash",
	}
	for in, want := range versionless {
		if got := purlWithoutVersion(in); got != want {
			t.Errorf("purlWithoutVersion(%q) = %q, want %q", in, got, want)
		}
	}

	version := map[string]string{
		"pkg:npm/lodash@4.17.21":   "4.17.21",
		"pkg:npm/@scope/pkg@1.0.0": "1.0.0",
		"pkg:npm/lodash":           "",
	}
	for in, want := range version {
		if got := purlVersion(in); got != want {
			t.Errorf("purlVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLooksLikeRange(t *testing.T) {
	for _, s := range []string{">=1.0.0 <2.0.0", "^1.2.3", "~1.2", "1.0.0 - 2.0.0", "[1.0,2.0)", "*"} {
		if !looksLikeRange(s) {
			t.Errorf("looksLikeRange(%q) = false", s)
		}
	}
	for _, s := range []string{"1.2.3", "v1.2.3", "4.17.21"} {
		if looksLikeRange(s) {
			t.Errorf("looksLikeRange(%q) = true", s)
		}
	}
}
