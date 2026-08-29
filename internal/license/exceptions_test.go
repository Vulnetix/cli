package license

import (
	"testing"
	"time"
)

func mustExceptions(t *testing.T, doc string) *ExceptionSet {
	t.Helper()
	set, err := ParseExceptions([]byte(doc))
	if err != nil {
		t.Fatalf("ParseExceptions: %v", err)
	}
	return set
}

var testNow = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

func TestBlanketExceptionPrefixMatch(t *testing.T) {
	set := mustExceptions(t, `
blanket:
  - license: MPL-2.0
    reason: file-level copyleft, unmodified
    approver: security@example.com
    approvedDate: 2026-08-01
`)
	// The exception names MPL-2.0. It must also cover the variant spelling: they
	// are the same licence, and requiring a separate entry would mean an
	// exception that silently stops applying when a dependency's metadata gets
	// more precise.
	for _, id := range []string{"MPL-2.0", "MPL-2.0-no-copyleft-exception"} {
		p := PackageLicense{PackageName: "lib", Ecosystem: "npm", LicenseSpdxID: id}
		applied, ok := set.Match(p, "", testNow)
		if !ok {
			t.Errorf("MPL-2.0 exception did not cover %q", id)
			continue
		}
		if applied.Kind != "blanket" {
			t.Errorf("kind = %q", applied.Kind)
		}
	}
	// It must not cover an unrelated licence that happens to share a prefix
	// boundary.
	p := PackageLicense{PackageName: "lib", Ecosystem: "npm", LicenseSpdxID: "MPL-1.1"}
	if _, ok := set.Match(p, "", testNow); ok {
		t.Error("an MPL-2.0 exception covered MPL-1.1")
	}
}

func TestPackageExceptionPurlGlob(t *testing.T) {
	set := mustExceptions(t, `
packages:
  - purl: pkg:golang/github.com/hashicorp/*
    license: MPL-2.0
    reason: vendored, unmodified
    approver: security@example.com
`)
	covered := PackageLicense{
		PackageName: "github.com/hashicorp/golang-lru", PackageVersion: "v0.5.4",
		Ecosystem: "golang", LicenseSpdxID: "MPL-2.0",
	}
	if _, ok := set.Match(covered, "", testNow); !ok {
		t.Error("the glob did not cover a hashicorp module")
	}

	// A different org must not be covered.
	other := PackageLicense{
		PackageName: "github.com/other/thing", Ecosystem: "golang", LicenseSpdxID: "MPL-2.0",
	}
	if _, ok := set.Match(other, "", testNow); ok {
		t.Error("the hashicorp glob covered a different organisation")
	}

	// The licence narrows the claim: the same package under GPL is not covered.
	wrongLicense := covered
	wrongLicense.LicenseSpdxID = "GPL-3.0-only"
	if _, ok := set.Match(wrongLicense, "", testNow); ok {
		t.Error("an MPL-2.0-scoped exception covered a GPL package")
	}
}

// TestPackageExceptionSurvivesVersionBump pins that an exception is written
// against a package, not a package version — otherwise it would silently lapse
// on the next dependency bump, which is the opposite of an auditable process.
func TestPackageExceptionSurvivesVersionBump(t *testing.T) {
	set := mustExceptions(t, `
packages:
  - purl: pkg:golang/github.com/hashicorp/golang-lru@v0.5.4
    reason: vendored
`)
	for _, version := range []string{"v0.5.4", "v1.0.2", "v2.0.0"} {
		p := PackageLicense{
			PackageName: "github.com/hashicorp/golang-lru", PackageVersion: version,
			Ecosystem: "golang", LicenseSpdxID: "MPL-2.0",
		}
		if _, ok := set.Match(p, "", testNow); !ok {
			t.Errorf("the exception did not cover version %s", version)
		}
	}
}

func TestPackageExceptionNameSubstring(t *testing.T) {
	set := mustExceptions(t, `
packages:
  - name: golang-lru
    reason: widely used LRU cache
`)
	// The short name and the fully-qualified module path are both in
	// circulation; an exception written for one must cover the other.
	p := PackageLicense{
		PackageName: "github.com/hashicorp/golang-lru", Ecosystem: "golang", LicenseSpdxID: "MPL-2.0",
	}
	if _, ok := set.Match(p, "", testNow); !ok {
		t.Error("a short-name exception did not cover the fully-qualified module path")
	}
}

// TestPackageExceptionNameIsSegmentAnchored pins the boundary. Substring
// matching would make an exception for "gpl-lib" cover "agpl-lib" — a different
// and stricter licence. An exception that quietly covers more than it names is
// the worst failure this file can have.
func TestPackageExceptionNameIsSegmentAnchored(t *testing.T) {
	set := mustExceptions(t, `
packages:
  - name: gpl-lib
    reason: not distributed
`)
	covered := []string{"gpl-lib", "github.com/acme/gpl-lib", "@acme/gpl-lib"}
	for _, name := range covered {
		p := PackageLicense{PackageName: name, Ecosystem: "npm", LicenseSpdxID: "GPL-3.0-only"}
		if _, ok := set.Match(p, "", testNow); !ok {
			t.Errorf("the exception did not cover %q", name)
		}
	}
	notCovered := []string{"agpl-lib", "gpl-lib-extra", "notgpl-lib", "github.com/acme/agpl-lib"}
	for _, name := range notCovered {
		p := PackageLicense{PackageName: name, Ecosystem: "npm", LicenseSpdxID: "AGPL-3.0-only"}
		if _, ok := set.Match(p, "", testNow); ok {
			t.Errorf("a gpl-lib exception covered %q", name)
		}
	}
}

// TestExceptionExpiry is the point of recording an expiry: an exception that
// outlives its review must stop working, and must say so.
func TestExceptionExpiry(t *testing.T) {
	set := mustExceptions(t, `
blanket:
  - license: MPL-2.0
    reason: interim approval pending review
    approver: security@example.com
    expires: 2026-08-14
`)
	p := PackageLicense{PackageName: "lib", Ecosystem: "npm", LicenseSpdxID: "MPL-2.0"}

	// Valid the day before.
	if _, ok := set.Match(p, "", time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)); !ok {
		t.Error("the exception did not apply before its expiry")
	}
	// The expiry date is inclusive: valid throughout the 14th.
	if _, ok := set.Match(p, "", time.Date(2026, 8, 14, 23, 0, 0, 0, time.UTC)); !ok {
		t.Error("the exception lapsed during its own expiry date")
	}
	// Lapsed on the 15th, and reported as lapsed rather than absent.
	applied, ok := set.Match(p, "", testNow)
	if ok {
		t.Fatal("an expired exception still exempted the finding")
	}
	if !applied.Expired {
		t.Error("the lapse was not reported; the user has no reason to look at the expiry they wrote")
	}
}

func TestExceptionProjectScope(t *testing.T) {
	set := mustExceptions(t, `
packages:
  - name: gpl-tool
    reason: internal tooling only
    projects: [internal-cli]
`)
	p := PackageLicense{PackageName: "gpl-tool", Ecosystem: "npm", LicenseSpdxID: "GPL-3.0-only"}

	if _, ok := set.Match(p, "internal-cli", testNow); !ok {
		t.Error("the exception did not apply to its own project")
	}
	if _, ok := set.Match(p, "payment-service", testNow); ok {
		t.Error("a project-scoped exception applied outside its project")
	}
}

func TestExceptionValidation(t *testing.T) {
	bad := map[string]string{
		"wrong apiVersion":        "apiVersion: nope/v1\n",
		"wrong kind":              "kind: NotExceptions\n",
		"blanket needs a licence": "blanket:\n  - reason: because\n",
		// An exception nobody can explain is indistinguishable from a mistake.
		"blanket needs a reason": "blanket:\n  - license: MIT\n",
		"package needs a target": "packages:\n  - reason: because\n",
		"package needs a reason": "packages:\n  - name: foo\n",
		"expiry must be a date":  "blanket:\n  - license: MIT\n    reason: r\n    expires: soon\n",
	}
	for name, doc := range bad {
		if _, err := ParseExceptions([]byte(doc)); err == nil {
			t.Errorf("%s: ParseExceptions accepted %q", name, doc)
		}
	}
}

func TestExpiringReturnsAWorkQueue(t *testing.T) {
	set := mustExceptions(t, `
blanket:
  - license: MPL-2.0
    reason: a
    expires: 2026-09-01
  - license: EPL-2.0
    reason: b
    expires: 2026-08-20
packages:
  - name: never-expires
    reason: c
`)
	// Nothing lapses in the next week except EPL.
	within7 := set.Expiring(testNow, 7*24*time.Hour)
	if len(within7) != 1 || within7[0].Match != "EPL-2.0" {
		t.Fatalf("Expiring(7d) = %+v, want just EPL-2.0", within7)
	}

	within30 := set.Expiring(testNow, 30*24*time.Hour)
	if len(within30) != 2 {
		t.Fatalf("Expiring(30d) = %d, want 2", len(within30))
	}
	// Soonest first, so the list reads as a work queue.
	if within30[0].Match != "EPL-2.0" {
		t.Errorf("Expiring is not ordered soonest-first: %+v", within30)
	}
}

// TestEvaluateMarksExemptions is the governing rule end-to-end: exempted
// findings are retained and badged, and the counts split.
func TestEvaluateMarksExemptions(t *testing.T) {
	packages := []PackageLicense{
		pkg("gpl-lib", "GPL-3.0-only", CategoryStrongCopyleft, "runtime"),
		pkg("agpl-lib", "AGPL-3.0-only", CategoryStrongCopyleft, "runtime"),
	}
	set := mustExceptions(t, `
packages:
  - name: gpl-lib
    reason: not distributed, internal service only
    approver: security@example.com
    approvedDate: 2026-08-01
    expires: 2027-08-01
`)

	res := Evaluate(packages, EvalConfig{Mode: "inclusive", Exceptions: set, Now: testNow})

	copyleft := findingsByCategory(res, "copyleft-in-production")
	if len(copyleft) != 2 {
		t.Fatalf("copyleft findings = %d, want 2 — an exempted finding is retained, not dropped", len(copyleft))
	}

	var exempted, live int
	for _, f := range copyleft {
		if f.Exempted {
			exempted++
			if f.ExemptionReason == "" || f.ExemptionLabel == "" {
				t.Errorf("%s is exempted but carries no attribution", f.Package.PackageName)
			}
		} else {
			live++
		}
	}
	if exempted != 1 || live != 1 {
		t.Errorf("exempted = %d, live = %d, want 1 and 1", exempted, live)
	}
	if res.Summary.Exempted != 1 {
		t.Errorf("Summary.Exempted = %d, want 1", res.Summary.Exempted)
	}
	if res.Summary.Effective != len(res.Findings)-1 {
		t.Errorf("Summary.Effective = %d, want %d", res.Summary.Effective, len(res.Findings)-1)
	}
}

// TestEvaluateReportsExpiredExceptions pins that a lapse surfaces as a lapse
// rather than as an unexplained new violation.
func TestEvaluateReportsExpiredExceptions(t *testing.T) {
	packages := []PackageLicense{pkg("gpl-lib", "GPL-3.0-only", CategoryStrongCopyleft, "runtime")}
	set := mustExceptions(t, `
packages:
  - name: gpl-lib
    reason: interim approval
    expires: 2026-01-01
`)

	res := Evaluate(packages, EvalConfig{Mode: "inclusive", Exceptions: set, Now: testNow})
	copyleft := findingsByCategory(res, "copyleft-in-production")
	if len(copyleft) != 1 {
		t.Fatalf("findings = %d", len(copyleft))
	}
	f := copyleft[0]
	if f.Exempted {
		t.Error("an expired exception still exempted the finding")
	}
	if !f.ExemptionExpired {
		t.Error("the finding does not say its exception lapsed")
	}
	if res.Summary.ExpiredExceptions != 1 {
		t.Errorf("Summary.ExpiredExceptions = %d, want 1", res.Summary.ExpiredExceptions)
	}
}

func TestExceptionSetNilSafe(t *testing.T) {
	var set *ExceptionSet
	p := PackageLicense{PackageName: "x", Ecosystem: "npm", LicenseSpdxID: "MIT"}
	if _, ok := set.Match(p, "", testNow); ok {
		t.Error("a nil exception set matched")
	}
	if got := set.Expiring(testNow, time.Hour); got != nil {
		t.Errorf("a nil exception set returned %+v", got)
	}
}
