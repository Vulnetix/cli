package scan

import "testing"

func exactFinding(rng, installed string) EnrichedVuln {
	return EnrichedVuln{
		VulnFinding:   VulnFinding{CveID: "CVE-2024-6783", PackageName: "vue-template-compiler", PackageVer: installed, Ecosystem: "npm"},
		AffectedRange: rng,
	}
}

// An advisory that states only specific releases is often a sample of the affected
// span (cve.org's own record is 2.0.0 through 2.7.16). An install newer than every
// listed release is therefore not ruled out; it was, and 2.7.16, the last affected
// release, was reported as safe.
func TestInstallNewerThanEveryListedExactVersionIsNotRuledOut(t *testing.T) {
	v := EvaluateVerdict(exactFinding("= 2.0.0", "2.7.16"))
	if v.Verdict != VerdictUnverified {
		t.Fatalf("verdict = %q, want unverified: a lone exact version is not the whole span", v.Verdict)
	}
	if !v.Verdict.Counts() {
		t.Error("an unverified finding must still count, so it is not hidden")
	}
}

// The listed release itself is affected, and an install older than every listed
// release, or between them, is unchanged: the rule is only about "newer than all".
func TestExactVersionRuleLeavesTheOtherCasesAlone(t *testing.T) {
	if v := EvaluateVerdict(exactFinding("= 2.0.0", "2.0.0")).Verdict; v != VerdictAffected {
		t.Errorf("the listed release = %q, want affected", v)
	}
	if v := EvaluateVerdict(exactFinding("= 2.0.0", "1.9.0")).Verdict; v != VerdictNotAffected {
		t.Errorf("older than the listed release = %q, want not affected as before", v)
	}
	if v := EvaluateVerdict(exactFinding("= 2.0.0 || = 3.0.0", "2.5.0")).Verdict; v != VerdictNotAffected {
		t.Errorf("between two listed releases = %q, want not affected as before", v)
	}
	// A real bound still decides.
	if v := EvaluateVerdict(exactFinding(">= 2.0.0, <= 2.5.0", "2.7.16")).Verdict; v != VerdictNotAffected {
		t.Errorf("outside a bounded range = %q, want not affected", v)
	}
}

// A range that ends at a development build ("< 1.85.0-dev.0.20260825072537") appears,
// under semver, to contain every 1.84.x release, but a commit in a development cycle
// cannot be placed against the releases cut from it. OSV's record for CVE-2026-84445
// excludes grpc 1.84.0, and four repos reported it as affected.
func TestReleaseInsideARangeEndedByADevBuildIsNotCalledAffected(t *testing.T) {
	ev := EnrichedVuln{
		VulnFinding:   VulnFinding{CveID: "CVE-2026-84445", PackageName: "google.golang.org/grpc", PackageVer: "1.84.0", Ecosystem: "golang"},
		AffectedRange: ">=1.84.0-dev, <1.85.0-dev.0.20260825072537",
	}
	v := EvaluateVerdict(ev)
	if v.Verdict != VerdictUnverified || v.Basis != "range-not-comparable" {
		t.Fatalf("verdict = %q basis %q, want unverified/range-not-comparable", v.Verdict, v.Basis)
	}
	// An ordinary bounded range is untouched.
	ev.AffectedRange = ">=1.0.0, <2.0.0"
	ev.PackageVer = "1.5.0"
	if got := EvaluateVerdict(ev).Verdict; got != VerdictAffected {
		t.Errorf("a plain bounded range = %q, want affected", got)
	}
	// An install that is itself a pre-release is judged by the normal rules.
	ev.AffectedRange = ">=1.84.0-dev, <1.85.0-dev.0.20260825072537"
	ev.PackageVer = "1.84.1-dev.0.20260825000000"
	if got := EvaluateVerdict(ev).Verdict; got == VerdictUnverified {
		t.Errorf("a pre-release install should not be routed through the release rule, got %q", got)
	}
}
