package report

import (
	"reflect"
	"testing"

	"github.com/vulnetix/cli/v3/internal/scan"
)

func aliasAdv(id string, v scan.Verdict, aliases ...string) Advisory {
	return Advisory{
		ID: id, Severity: "high", Verdict: scan.VerdictResult{Verdict: v},
		Ev: scan.EnrichedVuln{VulnFinding: scan.VulnFinding{CveID: id, Aliases: aliases}},
	}
}

func TestFoldAliasesMergesOneVulnerabilityUnderManyIDs(t *testing.T) {
	cve := aliasAdv("CVE-2018-16487", scan.VerdictAffected, "SNYK-JS-LODASH-73638", "GHSA-4xc9-xhrj-v574")
	snyk := aliasAdv("SNYK-JS-LODASH-73638", scan.VerdictAffected, "CVE-2018-16487")
	snyk.Exploits = 5
	snyk.Signals = []Signal{{Label: "PoC exploit", Strong: true}}
	other := aliasAdv("CVE-2020-8203", scan.VerdictAffected)

	got := foldAliases([]Advisory{snyk, other, cve})
	if len(got) != 2 {
		t.Fatalf("want 2 advisories, got %d: %+v", len(got), got)
	}
	var kept Advisory
	for _, a := range got {
		if a.ID == "CVE-2018-16487" {
			kept = a
		}
	}
	if kept.ID == "" {
		t.Fatalf("the CVE should be the one kept: %+v", got)
	}
	if !reflect.DeepEqual(kept.AlsoKnownAs, []string{"SNYK-JS-LODASH-73638"}) {
		t.Errorf("AlsoKnownAs = %v", kept.AlsoKnownAs)
	}
	if kept.Exploits != 5 || len(kept.Signals) != 1 {
		t.Errorf("folded advisory lost urgency: exploits=%d signals=%v", kept.Exploits, kept.Signals)
	}
}

// An alias group that holds a second vulnerability must not hide a finding the
// scan established when the other was not.
func TestFoldAliasesKeepsDifferentVerdictsApart(t *testing.T) {
	a := aliasAdv("CVE-2024-0001", scan.VerdictAffected, "GHSA-aaaa-bbbb-cccc")
	b := aliasAdv("GHSA-aaaa-bbbb-cccc", scan.VerdictUnverified, "CVE-2024-0001")
	if got := foldAliases([]Advisory{a, b}); len(got) != 2 {
		t.Fatalf("different verdicts must stay separate, got %d", len(got))
	}
}

func TestFoldAliasesLeavesUnrelatedAdvisoriesAlone(t *testing.T) {
	in := []Advisory{aliasAdv("CVE-1", scan.VerdictAffected), aliasAdv("CVE-2", scan.VerdictAffected)}
	if got := foldAliases(in); len(got) != 2 {
		t.Fatalf("got %d", len(got))
	}
}

func TestExplainFindsAFoldedIdentifier(t *testing.T) {
	a := aliasAdv("CVE-2018-16487", scan.VerdictAffected)
	a.AlsoKnownAs = []string{"SNYK-JS-LODASH-73638"}
	r := Report{Packages: []Package{{Name: "lodash", Version: "4.17.4", Advisories: []Advisory{a}}}}
	if got := FindExplain(r, "snyk-js-lodash-73638"); len(got) != 1 || len(got[0].Advisories) != 1 {
		t.Fatalf("folded id not found: %+v", got)
	}
}

// A polluted alias group once chained six distinct werkzeug CVEs into one row.
// Two CVEs are two vulnerabilities, and a one-sided claim is not enough.
func TestFoldAliasesNeverChainsDistinctCVEs(t *testing.T) {
	polluted := aliasAdv("CVE-2024-49766", scan.VerdictAffected,
		"CVE-2024-34069", "CVE-2024-49767", "GHSA-29vq-49wr-vm6x", "GHSA-2g68-c3qc-8985")
	b := aliasAdv("CVE-2024-34069", scan.VerdictAffected, "GHSA-2g68-c3qc-8985")
	c := aliasAdv("CVE-2024-49767", scan.VerdictAffected)
	g1 := aliasAdv("GHSA-2g68-c3qc-8985", scan.VerdictAffected, "CVE-2024-34069")
	g2 := aliasAdv("GHSA-29vq-49wr-vm6x", scan.VerdictAffected)
	got := foldAliases([]Advisory{polluted, b, c, g1, g2})
	// b+g1 fold (mutual); the polluted CVE absorbs nothing.
	if len(got) != 4 {
		t.Fatalf("want 4 rows (only the mutual CVE/GHSA pair folds), got %d: %+v", len(got), got)
	}
	for _, a := range got {
		if a.ID == "CVE-2024-49766" && len(a.AlsoKnownAs) != 0 {
			t.Errorf("the polluted group absorbed %v", a.AlsoKnownAs)
		}
	}
}

// The row is named by the most canonical identifier, not the one that sorts last.
func TestFoldAliasesNamesTheRowByTheCanonicalID(t *testing.T) {
	gms := aliasAdv("GMS-2022-11", scan.VerdictAffected, "GHSA-64g7-mvw6-v9qj")
	ghsa := aliasAdv("GHSA-64g7-mvw6-v9qj", scan.VerdictAffected, "GMS-2022-11")
	got := foldAliases([]Advisory{gms, ghsa})
	if len(got) != 1 || got[0].ID != "GHSA-64g7-mvw6-v9qj" || len(got[0].AlsoKnownAs) != 1 {
		t.Fatalf("got %+v", got)
	}
}

// The server caps alias lists, so the CVE side of a SNYK twin often omits it. The
// SNYK record's own single, unambiguous claim is enough.
func TestFoldAliasesAcceptsAnUnambiguousOneSidedClaim(t *testing.T) {
	cve := aliasAdv("CVE-2021-23337", scan.VerdictAffected, "GHSA-35jh-r3h4-6jhm")
	snyk := aliasAdv("SNYK-JS-LODASH-1040724", scan.VerdictAffected, "CVE-2021-23337")
	got := foldAliases([]Advisory{cve, snyk})
	if len(got) != 1 || got[0].ID != "CVE-2021-23337" || len(got[0].AlsoKnownAs) != 1 {
		t.Fatalf("got %+v", got)
	}
}

// A record that lists several ids of one family claims none of them.
func TestFoldAliasesIgnoresAnAmbiguousClaim(t *testing.T) {
	multi := aliasAdv("GMS-2020-1", scan.VerdictAffected, "CVE-2020-0001", "CVE-2020-0002")
	a := aliasAdv("CVE-2020-0001", scan.VerdictAffected)
	b := aliasAdv("CVE-2020-0002", scan.VerdictAffected)
	if got := foldAliases([]Advisory{multi, a, b}); len(got) != 3 {
		t.Fatalf("an ambiguous claim must not fold anything, got %d", len(got))
	}
}
