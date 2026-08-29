package license

import (
	"testing"
)

func pkg(name, spdxID string, cat Category, scope string) PackageLicense {
	return PackageLicense{
		PackageName: name, PackageVersion: "1.0.0", Ecosystem: "npm",
		Scope: scope, LicenseSpdxID: spdxID,
		Record: &LicenseRecord{SpdxID: spdxID, Name: spdxID, Category: cat, IsOsiApproved: true},
	}
}

func findingsByCategory(res *AnalysisResult, category string) []Finding {
	var out []Finding
	for _, f := range res.Findings {
		if f.Category == category {
			out = append(out, f)
		}
	}
	return out
}

// TestDefaultPolicyPreservesBehaviour is the compatibility lock. The default
// policy must reproduce exactly what the evaluator did before policies existed:
// adopting a policy is a deliberate act, not something an upgrade does to a
// team's build.
func TestDefaultPolicyPreservesBehaviour(t *testing.T) {
	p := DefaultPolicy()

	// Only strong copyleft carries a severity.
	if got := p.SeverityFor(CategoryStrongCopyleft, ""); got != "high" {
		t.Errorf("strong-copyleft = %q, want high", got)
	}
	for _, cat := range []Category{CategoryPermissive, CategoryPublicDomain, CategoryWeakCopyleft, CategoryProprietary} {
		if got := p.SeverityFor(cat, ""); got != "" {
			t.Errorf("%s = %q; the default must not start flagging categories that were not flagged before", cat, got)
		}
	}
	// No scope is ignored, so no rule silently stops firing on upgrade.
	for _, scope := range []string{"development", "dev", "test", "optional", "runtime", ""} {
		if !p.EvaluatesScope(scope, "") {
			t.Errorf("default policy ignores scope %q; findings reported yesterday would vanish today", scope)
		}
	}
	if p.UnknownFor("") != UnknownWarn {
		t.Errorf("unknown handling = %q, want warn", p.UnknownFor(""))
	}
}

func TestPolicyCategoryOverride(t *testing.T) {
	p, err := ParsePolicy([]byte(`
apiVersion: vulnetix.com/v1
kind: LicensePolicy
categories:
  strong-copyleft: [MPL-2.0]
severity:
  strong-copyleft: critical
`))
	if err != nil {
		t.Fatal(err)
	}
	// The embedded database classifies MPL-2.0 as weak copyleft. An
	// organisation's counsel may disagree, and that decision belongs in their
	// policy rather than in a fork of this CLI.
	if got := p.CategoryFor("MPL-2.0", CategoryWeakCopyleft); got != CategoryStrongCopyleft {
		t.Errorf("CategoryFor(MPL-2.0) = %q, want the policy override", got)
	}
	// Case-insensitively, since SPDX ids are written every which way.
	if got := p.CategoryFor("mpl-2.0", CategoryWeakCopyleft); got != CategoryStrongCopyleft {
		t.Errorf("CategoryFor(mpl-2.0) = %q, want the policy override", got)
	}
	if got := p.CategoryFor("MIT", CategoryPermissive); got != CategoryPermissive {
		t.Errorf("CategoryFor(MIT) = %q, want the fallback", got)
	}
}

func TestPolicyPartialDocumentInheritsDefaults(t *testing.T) {
	// A policy that only sets one severity must not silently drop the rest.
	p, err := ParsePolicy([]byte("severity:\n  unknown: high\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.SeverityFor(CategoryUnknown, ""); got != "high" {
		t.Errorf("unknown = %q, want the override", got)
	}
	if got := p.SeverityFor(CategoryStrongCopyleft, ""); got != "high" {
		t.Errorf("strong-copyleft = %q, want the inherited default", got)
	}
}

func TestPolicyProjectOverride(t *testing.T) {
	p, err := ParsePolicy([]byte(`
severity:
  weak-copyleft: none
projects:
  payment-service:
    severity:
      weak-copyleft: high
    scopes:
      test: ignore
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.SeverityFor(CategoryWeakCopyleft, "payment-service"); got != "high" {
		t.Errorf("payment-service weak-copyleft = %q, want high", got)
	}
	if got := p.SeverityFor(CategoryWeakCopyleft, "docs-site"); got != "" {
		t.Errorf("docs-site weak-copyleft = %q, want the global none", got)
	}
	if p.EvaluatesScope("test", "payment-service") {
		t.Error("payment-service should ignore the test scope")
	}
	if !p.EvaluatesScope("test", "docs-site") {
		t.Error("docs-site has no override and should evaluate the test scope")
	}
}

func TestPolicyValidation(t *testing.T) {
	bad := []string{
		"apiVersion: wrong/v1\n",
		"kind: NotAPolicy\n",
		"severity:\n  made-up-category: high\n",
		"severity:\n  permissive: very-bad\n",
		"unknown: maybe\n",
		"scopes:\n  test: sometimes\n",
	}
	for _, doc := range bad {
		if _, err := ParsePolicy([]byte(doc)); err == nil {
			t.Errorf("ParsePolicy(%q) = nil error, want a validation failure", doc)
		}
	}
	if _, err := ParsePolicy([]byte("apiVersion: vulnetix.com/v1\nkind: LicensePolicy\n")); err != nil {
		t.Errorf("a minimal valid policy was rejected: %v", err)
	}
}

// TestPolicyDrivesEvaluation is the end-to-end: a policy override must change
// which findings the evaluator produces and at what severity.
func TestPolicyDrivesEvaluation(t *testing.T) {
	packages := []PackageLicense{
		pkg("mpl-lib", "MPL-2.0", CategoryWeakCopyleft, "runtime"),
		pkg("mit-lib", "MIT", CategoryPermissive, "runtime"),
	}

	// Default: weak copyleft is not a finding.
	res := Evaluate(packages, EvalConfig{Mode: "inclusive"})
	if got := findingsByCategory(res, "copyleft-in-production"); len(got) != 0 {
		t.Errorf("default policy produced %d copyleft findings, want 0", len(got))
	}

	// Policy reclassifies MPL-2.0 as strong copyleft at critical.
	p, err := ParsePolicy([]byte("categories:\n  strong-copyleft: [MPL-2.0]\nseverity:\n  strong-copyleft: critical\n"))
	if err != nil {
		t.Fatal(err)
	}
	res = Evaluate(packages, EvalConfig{Mode: "inclusive", Policy: p})
	got := findingsByCategory(res, "copyleft-in-production")
	if len(got) != 1 {
		t.Fatalf("policy produced %d copyleft findings, want 1", len(got))
	}
	if got[0].Severity != "critical" {
		t.Errorf("severity = %q, want critical", got[0].Severity)
	}
	if got[0].Package.PackageName != "mpl-lib" {
		t.Errorf("flagged %q", got[0].Package.PackageName)
	}
}

// TestPolicyScopeFiltering pins that an ignored scope produces no findings at
// all, not merely a lower severity.
//
// The copyleft rule was already gated on production scope before policies
// existed, so it cannot show this. The scope-independent rules can: an
// unresolved licence on a development dependency is reported by default and
// must disappear entirely once the policy declares that scope out of scope.
func TestPolicyScopeFiltering(t *testing.T) {
	packages := []PackageLicense{{
		PackageName: "mystery-buildtool", PackageVersion: "1.0.0", Ecosystem: "npm",
		Scope: "development", LicenseSpdxID: "UNKNOWN",
	}}

	res := Evaluate(packages, EvalConfig{Mode: "inclusive"})
	if len(res.Findings) == 0 {
		t.Fatal("default policy evaluates every scope, so this should produce findings")
	}

	p, err := ParsePolicy([]byte("scopes:\n  development: ignore\n"))
	if err != nil {
		t.Fatal(err)
	}
	res = Evaluate(packages, EvalConfig{Mode: "inclusive", Policy: p})
	if len(res.Findings) != 0 {
		t.Errorf("an ignored scope produced %d findings: %+v", len(res.Findings), res.Findings)
	}
}

func TestUnknownHandling(t *testing.T) {
	packages := []PackageLicense{{
		PackageName: "mystery", PackageVersion: "1.0.0", Ecosystem: "npm",
		Scope: "runtime", LicenseSpdxID: "UNKNOWN",
	}}

	tests := map[string]string{
		"":       "medium", // default: warn
		"warn":   "medium",
		"fail":   "high",
		"ignore": "",
	}
	for handling, wantSeverity := range tests {
		doc := "unknown: " + handling + "\n"
		if handling == "" {
			doc = "{}\n"
		}
		p, err := ParsePolicy([]byte(doc))
		if err != nil {
			t.Fatalf("ParsePolicy(%q): %v", doc, err)
		}
		res := Evaluate(packages, EvalConfig{Mode: "inclusive", Policy: p})
		got := findingsByCategory(res, "unknown-license")
		if wantSeverity == "" {
			if len(got) != 0 {
				t.Errorf("unknown: %s produced %d findings, want 0", handling, len(got))
			}
			continue
		}
		if len(got) != 1 {
			t.Fatalf("unknown: %s produced %d findings, want 1", handling, len(got))
		}
		if got[0].Severity != wantSeverity {
			t.Errorf("unknown: %s severity = %q, want %q", handling, got[0].Severity, wantSeverity)
		}
	}
}

func TestRecommendedPolicyIsStricterThanDefault(t *testing.T) {
	rec := RecommendedPolicy()
	if rec.SeverityFor(CategoryProprietary, "") == "" {
		t.Error("the recommended policy should flag proprietary licences")
	}
	if rec.EvaluatesScope("development", "") {
		t.Error("the recommended policy should ignore development scope")
	}
	// AGPL's obligation triggers on network use rather than distribution, which
	// the embedded database does not separate out.
	if got := rec.CategoryFor("AGPL-3.0-or-later", CategoryPermissive); got != CategoryStrongCopyleft {
		t.Errorf("AGPL-3.0-or-later = %q, want strong-copyleft", got)
	}
	if _, err := ParsePolicy(mustYAML(t, rec)); err != nil {
		t.Errorf("the recommended policy does not round-trip through its own parser: %v", err)
	}
}

func mustYAML(t *testing.T, p *Policy) []byte {
	t.Helper()
	data, err := p.MarshalYAML()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestPolicyNilSafe(t *testing.T) {
	var p *Policy
	if got := p.CategoryFor("MIT", CategoryPermissive); got != CategoryPermissive {
		t.Errorf("nil policy CategoryFor = %q", got)
	}
	if got := p.SeverityFor(CategoryStrongCopyleft, ""); got != "" {
		t.Errorf("nil policy SeverityFor = %q", got)
	}
	if !p.EvaluatesScope("test", "") {
		t.Error("nil policy should evaluate every scope")
	}
	if p.UnknownFor("") != UnknownWarn {
		t.Error("nil policy should warn on unknown")
	}
}
