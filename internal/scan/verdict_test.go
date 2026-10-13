package scan

import (
	"strings"
	"testing"
)

func TestEvaluateVerdict(t *testing.T) {
	cases := []struct {
		name      string
		ev        EnrichedVuln
		want      Verdict
		basis     string
		fixedIn   string
		matchedBy string
	}{
		{
			// The kospex report: PYSEC-2024-38, fastapi 0.135.1, fixed in 0.109.1.
			// The source flagged it as affected; the range it supplied says it is
			// not. It must not come out as a plain "affected" finding.
			name: "range excludes the install but the source flagged it: they disagree, so it is not ruled out",
			ev: EnrichedVuln{
				VulnFinding:   VulnFinding{CveID: "PYSEC-2024-38", PackageName: "fastapi", PackageVer: "0.135.1", Ecosystem: "pypi"},
				AffectedRange: "< 0.109.1", VersionStatus: "affected", Confirmed: true,
			},
			want: VerdictUnverified, basis: "conflict", fixedIn: "0.109.1", matchedBy: "package name and version",
		},
		{
			name: "fastapi: range excludes the install and the source had no opinion",
			ev: EnrichedVuln{
				VulnFinding:   VulnFinding{PackageName: "fastapi", PackageVer: "0.135.1", Ecosystem: "pypi"},
				AffectedRange: "< 0.109.1", VersionStatus: "unknown",
			},
			want: VerdictNotAffected, basis: "range", fixedIn: "0.109.1", matchedBy: "package name and version",
		},
		{
			name: "no range, install is past the recommended fix",
			ev: EnrichedVuln{
				VulnFinding:   VulnFinding{PackageName: "fastapi", PackageVer: "0.135.1", Ecosystem: "pypi"},
				VersionStatus: "unknown",
				Remediation:   &RemediationInfo{FixVersion: "0.109.1"},
			},
			want: VerdictLikelyNotAffected, basis: "recommended-fix", fixedIn: "0.109.1", matchedBy: "package name only",
		},
		{
			name: "install is inside the range",
			ev: EnrichedVuln{
				VulnFinding:   VulnFinding{PackageName: "requests", PackageVer: "2.19.1", Ecosystem: "pypi"},
				AffectedRange: ">= 2.3.0, < 2.31.0", VersionStatus: "affected", Confirmed: true,
			},
			want: VerdictAffected, basis: "range", fixedIn: "2.31.0", matchedBy: "package name and version",
		},
		{
			name: "source says affected and supplied no range",
			ev: EnrichedVuln{
				VulnFinding:   VulnFinding{PackageName: "x", PackageVer: "1.0.0"},
				VersionStatus: "affected", Confirmed: true,
			},
			want: VerdictAffected, basis: "source", matchedBy: "package name and version",
		},
		{
			name: "explicit unaffected from the source",
			ev: EnrichedVuln{
				VulnFinding:   VulnFinding{PackageName: "x", PackageVer: "1.0.0"},
				AffectedRange: "< 2.0.0", VersionStatus: "unaffected",
			},
			want: VerdictNotAffected, basis: "source", fixedIn: "2.0.0", matchedBy: "package name and version",
		},
		{
			name: "name-only match with nothing to compare: unknown is not safe",
			ev: EnrichedVuln{
				VulnFinding:   VulnFinding{PackageName: "x", PackageVer: "1.0.0"},
				VersionStatus: "unknown",
			},
			want: VerdictUnverified, basis: "none", matchedBy: "package name only",
		},
		{
			name: "wildcard range is not arithmetic evidence",
			ev: EnrichedVuln{
				VulnFinding:   VulnFinding{PackageName: "x", PackageVer: "1.0.0"},
				AffectedRange: "*", VersionStatus: "unknown",
			},
			want: VerdictUnverified, basis: "none", matchedBy: "package name only",
		},
		{
			name: "unparseable installed version",
			ev: EnrichedVuln{
				VulnFinding:   VulnFinding{PackageName: "x", PackageVer: "not a version"},
				AffectedRange: "< 2.0.0", VersionStatus: "unknown",
			},
			want: VerdictUnverified, basis: "unparseable-version", matchedBy: "package name only",
		},
		{
			name: "install is below the recommended fix and nothing else is known",
			ev: EnrichedVuln{
				VulnFinding:   VulnFinding{PackageName: "x", PackageVer: "1.0.0"},
				VersionStatus: "unknown",
				Remediation:   &RemediationInfo{FixVersion: "2.0.0"},
			},
			want: VerdictUnverified, basis: "none", matchedBy: "package name only",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := EvaluateVerdict(c.ev)
			if got.Verdict != c.want {
				t.Fatalf("verdict = %q, want %q (%s)", got.Verdict, c.want, got.Detail)
			}
			if got.Basis != c.basis {
				t.Errorf("basis = %q, want %q", got.Basis, c.basis)
			}
			if got.FixedIn != c.fixedIn {
				t.Errorf("fixedIn = %q, want %q", got.FixedIn, c.fixedIn)
			}
			if got.MatchedBy != c.matchedBy {
				t.Errorf("matchedBy = %q, want %q", got.MatchedBy, c.matchedBy)
			}
			if got.Detail == "" {
				t.Error("verdict carries no explanation")
			}
		})
	}
}

// A finding the advisory itself rules out must not fail a build; one it cannot
// rule out must.
func TestVerdictCounts(t *testing.T) {
	want := map[Verdict]bool{
		VerdictAffected:          true,
		VerdictUnverified:        true,
		VerdictLikelyNotAffected: false,
		VerdictNotAffected:       false,
		"":                       true, // a finding with no verdict yet is not exempt
	}
	for v, counts := range want {
		if v.Counts() != counts {
			t.Errorf("%q.Counts() = %v, want %v", v, v.Counts(), counts)
		}
	}
}

// The live PYSEC-2024-38 record: the affected range is a git commit, not a
// version. Calling it "affected" because a source flagged it, or "not affected"
// because the arithmetic failed, would both be claims nobody checked.
func TestCommitRangeIsUnverifiedAndSaysWhy(t *testing.T) {
	ev := EnrichedVuln{
		VulnFinding:   VulnFinding{CveID: "PYSEC-2024-38", PackageName: "fastapi", PackageVer: "0.135.1", Ecosystem: "pypi"},
		AffectedRange: "<9d34ad0ee8a0dfbbcce06f76c2d5d851085024fc", VersionStatus: "affected", Confirmed: true,
	}
	got := EvaluateVerdict(ev)
	if got.Verdict != VerdictUnverified || got.Basis != "range-not-comparable" {
		t.Fatalf("verdict = %q basis %q: %s", got.Verdict, got.Basis, got.Detail)
	}
	if !strings.Contains(got.Detail, "git commit (9d34ad0)") || !strings.Contains(got.Detail, "0.135.1") {
		t.Errorf("the explanation should name the commit and the version: %q", got.Detail)
	}
	if !got.Verdict.Counts() {
		t.Error("an unverifiable finding must still count: unknown is not safe")
	}

	// With a recommended fix the install has already passed, the same record is
	// likely not affected, which is what an authenticated scan can say.
	ev.Remediation = &RemediationInfo{FixVersion: "0.109.1"}
	if v := EvaluateVerdict(ev).Verdict; v != VerdictLikelyNotAffected {
		t.Errorf("with a recommended fix below the install: %q", v)
	}
}

func TestCommitInRange(t *testing.T) {
	for in, want := range map[string]string{
		"<9d34ad0ee8a0dfbbcce06f76c2d5d851085024fc": "9d34ad0",
		">= abcdef1, < fa7e3c9":                     "abcdef1",
		"< 2.32.4":                                  "",
		"=1234567":                                  "", // digits only: a version, not a commit
		"< 1.2.3-beta":                              "",
	} {
		if got := commitInRange(in); got != want {
			t.Errorf("commitInRange(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExactRangeIsClearedByAnyUpgrade(t *testing.T) {
	ev := EnrichedVuln{
		VulnFinding:   VulnFinding{PackageName: "requests", PackageVer: "2.19.1", Ecosystem: "pypi"},
		AffectedRange: "=2.19.1", VersionStatus: "affected", Confirmed: true,
	}
	got := EvaluateVerdict(ev)
	if got.Verdict != VerdictAffected || !got.AnyUpgradeClears {
		t.Fatalf("%+v", got)
	}
	ev.AffectedRange = "< 2.32.4"
	if EvaluateVerdict(ev).AnyUpgradeClears {
		t.Error("an open range is not cleared by any upgrade")
	}
}

// A precompiled RubyGem carries its platform in the version. Compared as written,
// "1.19.1-x86_64-linux-gnu" reads as a pre-release and falls outside "= 1.19.1",
// which hid real nokogiri advisories.
func TestPlatformGemsAreComparedByTheirRelease(t *testing.T) {
	for _, ver := range []string{"1.19.1", "1.19.1-x86_64-linux-gnu", "1.19.1-aarch64-linux-gnu", "1.19.1-arm64-darwin", "1.19.1-java"} {
		ev := EnrichedVuln{
			VulnFinding:   VulnFinding{CveID: "GHSA-x", PackageName: "nokogiri", PackageVer: ver, Ecosystem: "gem"},
			AffectedRange: "= 1.19.1", VersionStatus: "affected", Confirmed: true,
		}
		if got := EvaluateVerdict(ev); got.Verdict != VerdictAffected || got.Basis != "range" {
			t.Errorf("%s: %+v", ver, got)
		}
	}
	ev := EnrichedVuln{
		VulnFinding:   VulnFinding{CveID: "GHSA-x", PackageName: "nokogiri", PackageVer: "1.19.2-x86_64-linux-gnu", Ecosystem: "gem"},
		AffectedRange: "< 1.19.2", VersionStatus: "affected", Confirmed: true,
	}
	if v := EvaluateVerdict(ev).Verdict; v == VerdictAffected {
		t.Errorf("1.19.2 is past < 1.19.2, got %q", v)
	}
}

// Nothing about a disagreement may hide a finding.
func TestAConflictNeverHidesAFinding(t *testing.T) {
	ev := EnrichedVuln{
		VulnFinding:   VulnFinding{PackageName: "x", PackageVer: "2.0.0", Ecosystem: "pypi"},
		AffectedRange: "< 1.0.0", VersionStatus: "affected", Confirmed: true,
	}
	if v := EvaluateVerdict(ev); !v.Verdict.Counts() || v.Basis != "conflict" {
		t.Fatalf("a range/source conflict must keep counting: %+v", v)
	}
}
