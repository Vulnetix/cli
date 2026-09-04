package scaview

import (
	"strings"
	"testing"

	"github.com/vulnetix/cli/v3/internal/scan"
)

func v(id, sev string, cvss, epss float64, kev bool, exploits int) scan.EnrichedVuln {
	e := scan.EnrichedVuln{MaxSeverity: sev, CVSSScore: cvss, EPSSScore: epss}
	e.CveID = id
	e.InCisaKev = kev
	e.ExploitCount = exploits
	return e
}

// TestCardMatchesTheShippedEditorCard pins the exact text, because three
// surfaces render from this function and a whitespace change in one of them is
// a change to all three.
//
// The expected value is the card the VS Code extension shows on a vulnerable
// line in a lockfile, which is the experience the agent surface exists to match.
func TestCardMatchesTheShippedEditorCard(t *testing.T) {
	vulns := []scan.EnrichedVuln{
		v("CVE-2026-67320", "critical", 9.3, 0.004, false, 0),
		v("CVE-2026-67319", "critical", 9.3, 0.002, false, 0),
		v("CVE-2026-67318", "critical", 9.3, 0.004, false, 0),
		v("CVE-2026-67317", "critical", 9.3, 0.005, false, 0),
		v("CVE-2026-67316", "critical", 9.3, 0.004, false, 0),
	}
	// Twelve critical, six high and one medium: nineteen in total, and the
	// medium is deliberately absent from the split, because a reader deciding
	// whether to act does not need the tail.
	for i := 0; i < 7; i++ {
		vulns = append(vulns, v("CVE-2026-6730"+string(rune('0'+i)), "critical", 9.0, 0, false, 0))
	}
	for i := 0; i < 6; i++ {
		vulns = append(vulns, v("CVE-2026-6740"+string(rune('0'+i)), "high", 8.0, 0, false, 0))
	}
	vulns = append(vulns, v("CVE-2026-67500", "medium", 5.0, 0, false, 0))

	got := Card(Subject{
		Pkg:      Pkg{Name: "axios", Version: "1.17.0", Ecosystem: "npm"},
		Vulns:    vulns,
		OwnVulns: len(vulns),
		Fix:      Fix{State: FixNone, Reason: "target 1.17.0 is already installed"},
	})

	want := strings.Join([]string{
		"**axios@1.17.0** · npm",
		"",
		"19 vulnerabilities · 12 critical, 6 high",
		"",
		// Equal severity, so the tiebreak is the newest identifier, which is what
		// the shipped editor card shows on this package.
		"- `CVE-2026-67320` **critical** · CVSS 9.3 · EPSS 0.4%",
		"- `CVE-2026-67319` **critical** · CVSS 9.3 · EPSS 0.2%",
		"- `CVE-2026-67318` **critical** · CVSS 9.3 · EPSS 0.4%",
		"- `CVE-2026-67317` **critical** · CVSS 9.3 · EPSS 0.5%",
		"- `CVE-2026-67316` **critical** · CVSS 9.3 · EPSS 0.4%",
		"- …and 14 more",
		"",
		"**Exploits:** none known",
		"",
		"**Fix:** none available — target 1.17.0 is already installed",
		"",
	}, "\n")

	if got != want {
		t.Errorf("card text changed.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestCardForACleanPackage(t *testing.T) {
	got := Card(Subject{Pkg: Pkg{Name: "left-pad", Version: "1.3.0", Ecosystem: "npm"}})
	want := "**left-pad@1.3.0** · npm\n\nNo known vulnerabilities.\n"
	if got != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
}

// TestCardOmitsAnEmptyVersion covers the case an agent produces constantly: a
// package named without a pin. "left-pad@" reads as a truncation rather than as
// the absence of a version.
func TestCardOmitsAnEmptyVersion(t *testing.T) {
	got := Card(Subject{Pkg: Pkg{Name: "left-pad", Ecosystem: "npm"}})
	if strings.Contains(got, "left-pad@") {
		t.Errorf("empty version rendered as a dangling separator:\n%q", got)
	}
	if !strings.HasPrefix(got, "**left-pad** · npm") {
		t.Errorf("got:\n%q", got)
	}
}

// TestMaliciousPackageDoesNotClaimToBeClean guards a contradiction: a package a
// malware feed has named carries no advisories precisely because nobody files
// one against a package that should not exist.
func TestMaliciousPackageDoesNotClaimToBeClean(t *testing.T) {
	got := Card(Subject{
		Pkg:     Pkg{Name: "evil-pkg", Version: "1.0.0", Ecosystem: "npm"},
		Insight: &Insight{Malicious: true},
	})
	if strings.Contains(got, "No known vulnerabilities") {
		t.Errorf("malicious package claims to be clean:\n%s", got)
	}
	if !strings.Contains(got, "Remove it; a version bump is not a fix") {
		t.Errorf("malicious package must say a bump will not help:\n%s", got)
	}
}

// TestAbsenceIsDistinguishedFromNotLooking is the discipline the whole package
// exists to preserve: "none found" and "not checked" are opposite claims that
// render as the same empty section if collapsed.
func TestAbsenceIsDistinguishedFromNotLooking(t *testing.T) {
	base := Subject{
		Pkg:      Pkg{Name: "pkg", Version: "1.0.0", Ecosystem: "npm"},
		Vulns:    []scan.EnrichedVuln{v("CVE-2020-1", "high", 7.0, 0, false, 0)},
		OwnVulns: 1,
	}

	cases := []struct {
		name    string
		mutate  func(*Subject)
		want    string
		notWant string
	}{
		{"exploits found none", func(s *Subject) {}, "**Exploits:** none known", "Pro unlocks"},
		{"exploits withheld", func(s *Subject) { s.ExploitsGated = true }, "Pro unlocks exploit intel", "none known"},
		{"fix withheld", func(s *Subject) { s.Fix = Fix{State: FixGated} }, "Pro unlocks Safe-Harbour", "none available"},
		{"fix still resolving", func(s *Subject) { s.Fix = Fix{State: FixPending} }, "Resolving safe versions", "none available"},
		{"fix genuinely absent", func(s *Subject) { s.Fix = Fix{State: FixNone, Reason: "no safe version"} }, "none available — no safe version", "Pro unlocks"},
		{"fix available", func(s *Subject) { s.Fix = Fix{State: FixAvailable, Target: "2.0.0"} }, "**Quick fix:** bump to 2.0.0", "none available"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := base
			tc.mutate(&s)
			got := Card(s)
			if !strings.Contains(got, tc.want) {
				t.Errorf("missing %q:\n%s", tc.want, got)
			}
			if tc.notWant != "" && strings.Contains(got, tc.notWant) {
				t.Errorf("must not contain %q:\n%s", tc.notWant, got)
			}
		})
	}
}

func TestHeadline(t *testing.T) {
	cases := []struct {
		name string
		s    Subject
		want string
	}{
		{
			name: "direct",
			s: Subject{
				Pkg:      Pkg{Name: "lodash", Version: "4.17.20"},
				Vulns:    []scan.EnrichedVuln{v("CVE-2021-23337", "high", 7.2, 0, true, 0)},
				OwnVulns: 1,
			},
			want: "lodash@4.17.20: 1 vulnerability (1 high) — CVE-2021-23337 (CISA KEV)",
		},
		{
			name: "transitive only, so the named package is not the problem",
			s: Subject{
				Pkg:        Pkg{Name: "express", Version: "4.17.1"},
				Vulns:      []scan.EnrichedVuln{v("CVE-2022-1", "high", 7.0, 0, false, 0)},
				OwnVulns:   0,
				Introduced: []string{"qs@6.5.2"},
			},
			want: "express@4.17.1: 1 vulnerability (1 high) introduced via qs@6.5.2 — CVE-2022-1",
		},
		{
			name: "both its own and transitive",
			s: Subject{
				Pkg:        Pkg{Name: "express", Version: "4.17.1"},
				Vulns:      []scan.EnrichedVuln{v("CVE-2022-1", "high", 7.0, 0, false, 0)},
				OwnVulns:   1,
				Introduced: []string{"qs@6.5.2"},
			},
			want: "express@4.17.1: 1 vulnerability (1 high), including qs@6.5.2 pulled in transitively — CVE-2022-1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Headline(tc.s); got != tc.want {
				t.Errorf("got:  %q\nwant: %q", got, tc.want)
			}
		})
	}
}

// TestTopVulnPrefersACVEOverADatabaseIdentifier pins a ranking decision that is
// deliberately placed ahead of the exploit count: the same advisory arrives
// under both names with different per-source tallies, so ranking on the tally
// first picks a name by an accident of which database recorded more.
func TestTopVulnPrefersACVEOverADatabaseIdentifier(t *testing.T) {
	ghsa := v("GHSA-aaaa-bbbb-cccc", "critical", 9.0, 0, false, 99)
	cve := v("CVE-2021-44228", "critical", 9.0, 0, false, 1)
	if got := TopVuln([]scan.EnrichedVuln{ghsa, cve}); got.CveID != "CVE-2021-44228" {
		t.Errorf("TopVuln picked %q, want the CVE", got.CveID)
	}
}

func TestSeveritySplitOmitsTheTail(t *testing.T) {
	counts := map[string]int{"critical": 2, "high": 3, "medium": 9, "low": 40}
	if got := SeveritySplit(counts); got != "2 critical, 3 high" {
		t.Errorf("got %q, want the two worst buckets only", got)
	}
}
