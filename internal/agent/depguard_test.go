package agent

import (
	"strings"
	"testing"
	"time"

	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

func pkg(name, version string) Candidate {
	return Candidate{Name: name, Version: version, Ecosystem: "npm", Manager: "npm"}
}

func vuln(id, severity string, kev bool) scan.EnrichedVuln {
	v := scan.EnrichedVuln{MaxSeverity: severity}
	v.CveID = id
	v.InCisaKev = kev
	return v
}

func safe(versions ...string) []vdb.CliSafeHarbourVersion {
	out := make([]vdb.CliSafeHarbourVersion, 0, len(versions))
	for _, v := range versions {
		out = append(out, vdb.CliSafeHarbourVersion{Version: v})
	}
	return out
}

// TestSilenceWhenPolicySatisfied is the behaviour the whole guard exists to
// protect. Everything else is a special case of speaking up.
func TestSilenceWhenPolicySatisfied(t *testing.T) {
	cases := []struct {
		name string
		a    Assessment
	}{
		{
			name: "clean package, no safer version to move to",
			a:    Assessment{Candidate: pkg("axios", "1.7.9")},
		},
		{
			name: "clean package already at the safest version",
			a: Assessment{
				Candidate: pkg("axios", "1.7.9"),
				Insight:   &vdb.CliPackageInsight{SafeVersions: safe("1.7.9")},
			},
		},
		{
			name: "clean package beyond the safest version",
			a: Assessment{
				Candidate: pkg("axios", "1.8.0"),
				Insight:   &vdb.CliPackageInsight{SafeVersions: safe("1.7.9")},
			},
		},
		{
			name: "lookup could not answer",
			a:    Assessment{Candidate: pkg("axios", "1.0.0"), Unknown: true},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EvaluateDependency(DefaultPolicy(), []Assessment{tc.a})
			if got.Decision != Silent {
				t.Fatalf("decision = %v, want Silent\nmessage: %s", got.Decision, got.Message)
			}
			if got.Message != "" {
				t.Fatalf("message = %q, want empty", got.Message)
			}
		})
	}
}

func TestBlocksOnlyWhatIsNeverRight(t *testing.T) {
	cases := []struct {
		name string
		a    Assessment
		want Decision
	}{
		{
			name: "known-malicious package blocks",
			a: Assessment{
				Candidate: pkg("evil-pkg", "1.0.0"),
				Insight:   &vdb.CliPackageInsight{IsMalicious: true},
			},
			want: Block,
		},
		{
			name: "critical advisory on a known-exploited list blocks",
			a: Assessment{
				Candidate: pkg("log4j", "2.14.1"),
				Vulns:     []scan.EnrichedVuln{vuln("CVE-2021-44228", "critical", true)},
			},
			want: Block,
		},
		{
			name: "critical advisory with no exploitation evidence only warns",
			a: Assessment{
				Candidate: pkg("somepkg", "1.0.0"),
				Vulns:     []scan.EnrichedVuln{vuln("CVE-2020-1111", "critical", false)},
			},
			want: Inform,
		},
		{
			name: "high advisory only warns",
			a: Assessment{
				Candidate: pkg("somepkg", "1.0.0"),
				Vulns:     []scan.EnrichedVuln{vuln("CVE-2020-2222", "high", false)},
			},
			want: Inform,
		},
		{
			name: "end of life only warns",
			a: Assessment{
				Candidate: pkg("oldpkg", "1.0.0"),
				Insight:   &vdb.CliPackageInsight{IsEOL: true, EOLFrom: "2023-04-01"},
			},
			want: Inform,
		},
		{
			name: "a vulnerable package with somewhere safer to go warns",
			a: Assessment{
				Candidate: pkg("axios", "1.0.0"),
				Vulns:     []scan.EnrichedVuln{vuln("CVE-2020-3333", "medium", false)},
				Insight:   &vdb.CliPackageInsight{SafeVersions: safe("1.7.9")},
			},
			want: Inform,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EvaluateDependency(DefaultPolicy(), []Assessment{tc.a})
			if got.Decision != tc.want {
				t.Fatalf("decision = %v, want %v\nmessage: %s", got.Decision, tc.want, got.Message)
			}
		})
	}
}

// TestUnknownNeverBlocks pins the discipline the LSP encodes as Degradations:
// absence of an answer is not a verdict.
func TestUnknownNeverBlocks(t *testing.T) {
	got := EvaluateDependency(DefaultPolicy(), []Assessment{
		{Candidate: pkg("evil-pkg", "1.0.0"), Unknown: true,
			Insight: &vdb.CliPackageInsight{IsMalicious: true}},
	})
	if got.Decision != Silent {
		t.Fatalf("decision = %v, want Silent when the lookup did not answer", got.Decision)
	}
}

func TestBlockReportsWarningsToo(t *testing.T) {
	// The agent is about to pick something else, so the block names everything
	// worth knowing rather than only the reason it stopped.
	got := EvaluateDependency(DefaultPolicy(), []Assessment{
		{Candidate: pkg("evil-pkg", "1.0.0"), Insight: &vdb.CliPackageInsight{IsMalicious: true}},
		{
			Candidate: pkg("axios", "1.0.0"),
			Vulns:     []scan.EnrichedVuln{vuln("CVE-2020-5555", "high", false)},
			Insight:   &vdb.CliPackageInsight{SafeVersions: safe("1.7.9")},
		},
	})
	if got.Decision != Block {
		t.Fatalf("decision = %v, want Block", got.Decision)
	}
	if !strings.Contains(got.Message, "evil-pkg") || !strings.Contains(got.Message, "axios") {
		t.Fatalf("message names only some packages:\n%s", got.Message)
	}
}

func TestMaliciousPackageIsNotOfferedAVersionBump(t *testing.T) {
	got := EvaluateDependency(DefaultPolicy(), []Assessment{{
		Candidate: pkg("evil-pkg", "1.0.0"),
		Insight:   &vdb.CliPackageInsight{IsMalicious: true, SafeVersions: safe("2.0.0")},
	}})
	if !strings.Contains(got.Message, "Remove it; a version bump is not a fix") {
		t.Fatalf("malicious package must not be offered a bump:\n%s", got.Message)
	}
}

func TestStrategyChangesTheTarget(t *testing.T) {
	in := &vdb.CliPackageInsight{
		SafeVersions:   safe("1.5.0", "2.9.0"),
		LatestVersions: []vdb.CliVersionStamp{{Version: "3.0.0"}},
	}
	// A vulnerable package, so the question is only which target the strategy
	// picks. A clean one produces no target signal at all, whatever the
	// strategy.
	a := Assessment{
		Candidate: pkg("axios", "1.5.0"),
		Vulns:     []scan.EnrichedVuln{vuln("CVE-2020-4444", "medium", false)},
		Insight:   in,
	}

	// Already at the safest version: nothing to recommend, so the only signal
	// left is the advisory itself.
	p := DefaultPolicy()
	if got := EvaluateDependency(p, []Assessment{a}); got.Decision != Silent {
		t.Fatalf("safest: decision = %v, want Silent\n%s", got.Decision, got.Message)
	}

	// Under latest, a major bump is available but maxMajorBump refuses it, so
	// the guard still says nothing rather than recommending a rewrite.
	p.SafeHarbourStrategy = "latest"
	if got := EvaluateDependency(p, []Assessment{a}); got.Decision != Silent {
		t.Fatalf("latest with maxMajorBump 0: decision = %v, want Silent\n%s", got.Decision, got.Message)
	}

	// Allowing majors, the same package now has somewhere to go.
	p.MaxMajorBump = 2
	if got := EvaluateDependency(p, []Assessment{a}); got.Decision != Inform {
		t.Fatalf("latest with maxMajorBump 2: decision = %v, want Inform", got.Decision)
	}
}

func TestCooldownOnlyFiresWhenConfigured(t *testing.T) {
	published := time.Now().Add(-24 * time.Hour).UnixMilli()
	a := Assessment{
		Candidate: pkg("axios", "1.7.9"),
		Insight:   &vdb.CliPackageInsight{PublishedAt: &published},
	}

	if got := EvaluateDependency(DefaultPolicy(), []Assessment{a}); got.Decision != Silent {
		t.Fatalf("cooldown disabled: decision = %v, want Silent", got.Decision)
	}

	p := DefaultPolicy()
	p.CooldownDays = 7
	if got := EvaluateDependency(p, []Assessment{a}); got.Decision != Inform {
		t.Fatalf("cooldown 7d: decision = %v, want Inform", got.Decision)
	}
}

func TestUnpinnedRequest(t *testing.T) {
	for _, v := range []string{"", "^1.0.0", "~1.0.0", "latest", "*"} {
		if !isUnpinned(v) {
			t.Errorf("isUnpinned(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"1.0.0", "v1.2.3", "2.31.0"} {
		if isUnpinned(v) {
			t.Errorf("isUnpinned(%q) = true, want false", v)
		}
	}
}

func TestDisabledPolicyIsAlwaysSilent(t *testing.T) {
	off := false
	p := DefaultPolicy()
	p.Enabled = &off
	got := EvaluateDependency(p, []Assessment{{
		Candidate: pkg("evil-pkg", "1.0.0"),
		Insight:   &vdb.CliPackageInsight{IsMalicious: true},
	}})
	if got.Decision != Silent {
		t.Fatalf("decision = %v, want Silent when the surface is switched off", got.Decision)
	}
}

// TestUnpinnedIsSilentByDefault pins the correction that testing against real
// installs forced: `npm i axios` is how almost every install is written, so a
// guard that warns on the absence of a pin fires on nearly every command.
func TestUnpinnedIsSilentByDefault(t *testing.T) {
	got := EvaluateDependency(DefaultPolicy(), []Assessment{{
		Candidate: Candidate{Name: "left-pad", Ecosystem: "npm", Manager: "npm"},
		Resolved:  "1.3.0",
	}})
	if got.Decision != Silent {
		t.Fatalf("decision = %v, want Silent for a clean unpinned install\n%s", got.Decision, got.Message)
	}
}

// TestUnpinnedCanBeOptedInto keeps the signal available to a repository that
// wants it, since removing it from the default is a noise judgement rather than
// a claim that it does not matter.
func TestUnpinnedCanBeOptedInto(t *testing.T) {
	p := DefaultPolicy()
	p.DependencyGuard.Warn = append(p.DependencyGuard.Warn, SignalUnpinned)
	got := EvaluateDependency(p, []Assessment{{
		Candidate: Candidate{Name: "left-pad", Ecosystem: "npm", Manager: "npm"},
		Resolved:  "1.3.0",
	}})
	if got.Decision != Inform {
		t.Fatalf("decision = %v, want Inform once unpinned is opted into", got.Decision)
	}
	if !strings.Contains(got.Message, "resolves to 1.3.0") {
		t.Fatalf("message should name what it resolves to today:\n%s", got.Message)
	}
}

// TestCleanPackageWithANewerVersionIsSilent pins the second correction real
// installs forced: almost every package has a later release, so "there is a
// newer safe version" is a fact about the registry rather than about the
// decision being made. It is the answer to a problem, not a problem.
func TestCleanPackageWithANewerVersionIsSilent(t *testing.T) {
	got := EvaluateDependency(DefaultPolicy(), []Assessment{{
		Candidate: pkg("left-pad", "1.2.0"),
		Insight:   &vdb.CliPackageInsight{SafeVersions: safe("1.3.0")},
	}})
	if got.Decision != Silent {
		t.Fatalf("decision = %v, want Silent for a clean package\n%s", got.Decision, got.Message)
	}
}

// TestVulnerablePackageStillGetsTheTarget keeps the valuable half: when the
// requested version does carry advisories, where to go instead is the point.
func TestVulnerablePackageStillGetsTheTarget(t *testing.T) {
	got := EvaluateDependency(DefaultPolicy(), []Assessment{{
		Candidate: pkg("lodash", "4.17.20"),
		Vulns:     []scan.EnrichedVuln{vuln("CVE-2021-23337", "high", false)},
		Insight:   &vdb.CliPackageInsight{SafeVersions: safe("4.17.21")},
	}})
	if got.Decision != Inform {
		t.Fatalf("decision = %v, want Inform", got.Decision)
	}
	if !strings.Contains(got.Message, "bump to 4.17.21") {
		t.Fatalf("message should carry the target:\n%s", got.Message)
	}
}
