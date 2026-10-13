package scan

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

// pysec38 is the real affected record for PYSEC-2024-38 (abridged): a git range,
// the ecosystem range the scan response never surfaces, and enumerated versions.
func pysec38() map[string]any {
	return map[string]any{
		"identifier": "PYSEC-2024-38",
		"aliases":    []any{"CVE-2024-24762", "GHSA-qf9m-vfgh-m389"},
		"affected": []any{map[string]any{
			"packageName": "fastapi", "ecosystem": "pypi",
			"versions": []any{
				map[string]any{"version": "0", "lessThan": "9d34ad0ee8a0dfbbcce06f76c2d5d851085024fc", "status": "affected", "versionType": "GIT"},
				map[string]any{"version": "0", "lessThan": "0.109.1", "status": "affected", "versionType": "ECOSYSTEM"},
				map[string]any{"version": "0.1.0", "status": "affected", "versionType": "custom"},
				map[string]any{"version": "0.109.0", "status": "affected", "versionType": "custom"},
			},
		}},
	}
}

func fastapiFinding(id, ver string) EnrichedVuln {
	return EnrichedVuln{
		VulnFinding:   VulnFinding{CveID: id, PackageName: "fastapi", PackageVer: ver, Ecosystem: "pypi"},
		AffectedRange: "<9d34ad0ee8a0dfbbcce06f76c2d5d851085024fc", VersionStatus: "affected", Confirmed: true,
	}
}

func fetcher(records map[string]map[string]any, calls *int32) AffectedFetcher {
	return func(_ context.Context, id, _, _ string) (map[string]any, error) {
		atomic.AddInt32(calls, 1)
		if r, ok := records[id]; ok {
			return r, nil
		}
		return nil, errors.New("not found")
	}
}

// The reported case. The finding carries only the git range, so it is
// unverified; the advisory's own record says it was fixed in 0.109.1.
func TestResolveUnverifiedSettlesTheKospexFinding(t *testing.T) {
	var calls int32
	vs := []EnrichedVuln{fastapiFinding("PYSEC-2024-38", "0.135.1")}
	if EvaluateVerdict(vs[0]).Verdict != VerdictUnverified {
		t.Fatal("precondition: the finding starts unverified")
	}
	st := ResolveUnverified(context.Background(), vs, fetcher(map[string]map[string]any{"PYSEC-2024-38": pysec38()}, &calls), 4)

	got := EvaluateVerdict(vs[0])
	if got.Verdict != VerdictNotAffected || got.Basis != "range" || got.FixedIn != "0.109.1" {
		t.Fatalf("verdict = %+v", got)
	}
	if st.Resolved != 1 || st.NotAffected != 1 {
		t.Errorf("stats = %+v", st)
	}
}

// The CVE twin carries no entry for the package, so its verdict comes from the
// alias that does.
func TestResolveUnverifiedFollowsAliases(t *testing.T) {
	var calls int32
	cve := map[string]any{
		"identifier": "CVE-2024-24762",
		"aliases":    []any{"PYSEC-2024-38", "GHSA-qf9m-vfgh-m389"},
		"affected":   []any{map[string]any{"packageName": "connect", "ecosystem": "cloud"}},
	}
	vs := []EnrichedVuln{fastapiFinding("CVE-2024-24762", "0.135.1")}
	ResolveUnverified(context.Background(), vs, fetcher(map[string]map[string]any{
		"CVE-2024-24762": cve, "PYSEC-2024-38": pysec38(),
	}, &calls), 4)
	if v := EvaluateVerdict(vs[0]).Verdict; v != VerdictNotAffected {
		t.Fatalf("verdict = %q, want not_affected via the PYSEC alias", v)
	}
}

// Resolution can also say "affected": an install that is inside the ecosystem
// range stays a finding, now with the range and the fix behind it.
func TestResolveUnverifiedConfirmsAffected(t *testing.T) {
	var calls int32
	vs := []EnrichedVuln{fastapiFinding("PYSEC-2024-38", "0.100.0")}
	ResolveUnverified(context.Background(), vs, fetcher(map[string]map[string]any{"PYSEC-2024-38": pysec38()}, &calls), 4)
	got := EvaluateVerdict(vs[0])
	if got.Verdict != VerdictAffected || got.Basis != "range" || got.FixedIn != "0.109.1" {
		t.Fatalf("%+v", got)
	}
}

// An install listed only in the enumerated versions is affected, and must not
// come out as "outside the range".
func TestResolveUnverifiedHonoursEnumeratedVersions(t *testing.T) {
	var calls int32
	rec := pysec38()
	entry := rec["affected"].([]any)[0].(map[string]any)
	entry["versions"] = append(entry["versions"].([]any),
		map[string]any{"version": "0.200.0", "status": "affected", "versionType": "custom"})
	vs := []EnrichedVuln{fastapiFinding("PYSEC-2024-38", "0.200.0")}
	ResolveUnverified(context.Background(), vs, fetcher(map[string]map[string]any{"PYSEC-2024-38": rec}, &calls), 4)
	if v := EvaluateVerdict(vs[0]).Verdict; v != VerdictAffected {
		t.Fatalf("verdict = %q, want affected: the version is listed", v)
	}
}

// What it cannot settle it leaves alone, and it never turns "unknown" into "safe".
func TestResolveUnverifiedLeavesWhatItCannotSettle(t *testing.T) {
	var calls int32
	gitOnly := map[string]any{"affected": []any{map[string]any{
		"packageName": "fastapi", "ecosystem": "pypi",
		"versions": []any{map[string]any{"version": "0", "lessThan": "9d34ad0ee8a0dfbbcce06f76c2d5d851085024fc", "versionType": "GIT", "status": "affected"}},
	}}}
	otherPkg := map[string]any{"affected": []any{map[string]any{
		"packageName": "starlette", "ecosystem": "pypi",
		"versions": []any{map[string]any{"version": "0", "lessThan": "0.1", "status": "affected"}},
	}}}
	vs := []EnrichedVuln{fastapiFinding("A-1", "0.135.1"), fastapiFinding("B-2", "0.135.1"), fastapiFinding("C-3", "0.135.1")}
	before := vs[0]
	ResolveUnverified(context.Background(), vs, fetcher(map[string]map[string]any{"A-1": gitOnly, "B-2": otherPkg}, &calls), 4)
	for i, v := range vs {
		if EvaluateVerdict(v).Verdict != VerdictUnverified {
			t.Errorf("finding %d was settled without evidence: %+v", i, EvaluateVerdict(v))
		}
	}
	if vs[0].AffectedRange != before.AffectedRange || vs[0].VersionStatus != before.VersionStatus || vs[0].MatchMethod != before.MatchMethod {
		t.Error("an unsettled finding must be left exactly as it was")
	}
}

func TestResolveUnverifiedOnlyTouchesUnverifiedAndFetchesOnce(t *testing.T) {
	var calls int32
	checked := fastapiFinding("PYSEC-2024-38", "0.135.1")
	checked.AffectedRange = "< 0.200.0" // a comparable range: already settled
	vs := []EnrichedVuln{checked, fastapiFinding("PYSEC-2024-38", "0.135.1"), fastapiFinding("PYSEC-2024-38", "0.135.1")}
	vs[1].PackageName, vs[2].PackageName = "fastapi", "fastapi"
	ResolveUnverified(context.Background(), vs, fetcher(map[string]map[string]any{"PYSEC-2024-38": pysec38()}, &calls), 4)
	if calls != 1 {
		t.Errorf("one advisory should be fetched once, got %d fetches", calls)
	}
	if vs[0].MatchMethod != "" {
		t.Error("a finding whose version was already checkable must not be re-resolved")
	}
}

func TestSamePackageFoldsPyPISpellings(t *testing.T) {
	am := map[string]any{"packageName": "Typing_Extensions", "ecosystem": "pypi"}
	if !samePackage(am, "typing-extensions", "pypi") {
		t.Error("PyPI treats - _ . as one")
	}
	if samePackage(am, "typing-extensions", "npm") {
		t.Error("a different ecosystem is a different package")
	}
}

// The real record for PYSEC-2024-38 also carries a wildcard "every release" entry
// from a low-quality source. It must not outweigh the precise range.
func TestResolveUnverifiedIgnoresWildcardEntries(t *testing.T) {
	var calls int32
	rec := pysec38()
	entry := rec["affected"].([]any)[0].(map[string]any)
	entry["versions"] = append(entry["versions"].([]any),
		map[string]any{"version": "*", "status": "affected", "versionType": "custom"},
		map[string]any{"version": "0", "lessThan": "*", "status": "affected", "versionType": "GIT"})
	vs := []EnrichedVuln{fastapiFinding("PYSEC-2024-38", "0.135.3")}
	ResolveUnverified(context.Background(), vs, fetcher(map[string]map[string]any{"PYSEC-2024-38": rec}, &calls), 4)
	if v := EvaluateVerdict(vs[0]).Verdict; v != VerdictNotAffected {
		t.Fatalf("verdict = %q, want not_affected: a wildcard is not evidence", v)
	}

	// With nothing but a wildcard there is no evidence at all.
	only := map[string]any{"affected": []any{map[string]any{"packageName": "fastapi", "ecosystem": "pypi",
		"versions": []any{map[string]any{"version": "*", "status": "affected"}}}}}
	vs = []EnrichedVuln{fastapiFinding("X-1", "0.135.3")}
	ResolveUnverified(context.Background(), vs, fetcher(map[string]map[string]any{"X-1": only}, &calls), 4)
	if v := EvaluateVerdict(vs[0]).Verdict; v != VerdictUnverified {
		t.Fatalf("a wildcard alone must leave the finding unverified, got %q", v)
	}
}

// A wildcard range ("*") with a confirming source is "affected" on the source's
// say-so. When the advisory's own record shows the install is past the fix it must
// stop reporting vulnerable.
func TestWildcardFindingStopsReportingVulnerableOnceFixed(t *testing.T) {
	var calls int32
	wild := fastapiFinding("PYSEC-2024-38", "0.135.3")
	wild.AffectedRange = "*"
	if v := EvaluateVerdict(wild); v.Verdict != VerdictAffected || v.Basis != "source" {
		t.Fatalf("precondition: a wildcard finding starts as affected-by-source, got %+v", v)
	}
	vs := []EnrichedVuln{wild}
	ResolveUnverified(context.Background(), vs, fetcher(map[string]map[string]any{"PYSEC-2024-38": pysec38()}, &calls), 4)
	if got := EvaluateVerdict(vs[0]); got.Verdict != VerdictNotAffected || got.FixedIn != "0.109.1" {
		t.Fatalf("after the fix the wildcard finding must be not affected, got %+v", got)
	}

	// And one genuinely inside the vulnerable range stays a finding, now with its fix.
	still := fastapiFinding("PYSEC-2024-38", "0.100.0")
	still.AffectedRange = "*"
	vs = []EnrichedVuln{still}
	ResolveUnverified(context.Background(), vs, fetcher(map[string]map[string]any{"PYSEC-2024-38": pysec38()}, &calls), 4)
	if got := EvaluateVerdict(vs[0]); got.Verdict != VerdictAffected || got.FixedIn != "0.109.1" {
		t.Fatalf("a wildcard finding inside the range stays affected with its fix, got %+v", got)
	}

	// No usable record: it stays exactly as it was. Unknown is not safe.
	vs = []EnrichedVuln{wild}
	ResolveUnverified(context.Background(), vs, fetcher(nil, &calls), 4)
	if v := EvaluateVerdict(vs[0]).Verdict; v != VerdictAffected {
		t.Fatalf("with no record the finding must not change, got %q", v)
	}
}

// A long alias list that starts with distribution advisories and unrelated CVEs
// must still reach the GHSA or PYSEC twin that carries the ranges.
func TestResolveUnverifiedReachesTheRightAliasInALongList(t *testing.T) {
	var calls int32
	var aliases []any
	for _, a := range []string{"RHSA-2020:0850", "ALAS2-2019-1334", "SUSE-SU-2019:1487-1", "EUVD-2018-0131",
		"CVE-2019-9999", "CVE-2020-8888", "CVE-2021-7777", "GHSA-qf9m-vfgh-m389", "PYSEC-2024-38"} {
		aliases = append(aliases, a)
	}
	cve := map[string]any{"aliases": aliases, "affected": []any{}}
	vs := []EnrichedVuln{fastapiFinding("CVE-2024-24762", "0.135.1")}
	ResolveUnverified(context.Background(), vs, fetcher(map[string]map[string]any{
		"CVE-2024-24762": cve, "PYSEC-2024-38": pysec38(),
	}, &calls), 4)
	if v := EvaluateVerdict(vs[0]).Verdict; v != VerdictNotAffected {
		t.Fatalf("verdict = %q: the PYSEC alias sits behind seven others and must still be found", v)
	}
}

// Alias groups are not always clean. An alias record that says "affected" keeps
// the finding; only unanimous aliases may clear it.
func TestAliasEvidenceCannotClearAFindingAnotherAliasAffects(t *testing.T) {
	var calls int32
	// An older advisory for the same package: fixed in 0.109.1, so 0.120.0 is outside.
	older := pysec38()
	// A newer advisory for the same package, fixed in 0.130.0: 0.120.0 is inside.
	newer := map[string]any{"affected": []any{map[string]any{"packageName": "fastapi", "ecosystem": "pypi",
		"versions": []any{map[string]any{"version": "0", "lessThan": "0.130.0", "status": "affected", "versionType": "ECOSYSTEM"}}}}}
	cve := map[string]any{"aliases": []any{"PYSEC-2024-38", "GHSA-new"}}
	vs := []EnrichedVuln{fastapiFinding("CVE-2026-1", "0.120.0")}
	ResolveUnverified(context.Background(), vs, fetcher(map[string]map[string]any{
		"CVE-2026-1": cve, "PYSEC-2024-38": older, "GHSA-new": newer,
	}, &calls), 4)
	got := EvaluateVerdict(vs[0])
	if got.Verdict == VerdictNotAffected || got.Verdict == VerdictLikelyNotAffected {
		t.Fatalf("a contaminated alias group must not hide a real finding, got %+v", got)
	}
}

func werkzeugRecord(fixed string) map[string]any {
	return map[string]any{
		"identifier": "CVE-2026-1",
		"affected": []any{map[string]any{
			"packageName": "werkzeug", "ecosystem": "pypi",
			"versions": []any{map[string]any{"version": "0", "lessThan": fixed, "status": "affected", "versionType": "ECOSYSTEM"}},
		}},
	}
}

// The scan response often carries "= <installed>" and no fix. The recommended
// upgrade was then computed from the other advisories on the package and could
// land below the version that clears this one.
func TestResolveLearnsTheFixOfAnAffectedFindingThatNamesNone(t *testing.T) {
	var calls int32
	vs := []EnrichedVuln{{
		VulnFinding:   VulnFinding{CveID: "CVE-2026-1", PackageName: "werkzeug", PackageVer: "3.1.0", Ecosystem: "pypi"},
		AffectedRange: "=3.1.0", VersionStatus: "affected", Confirmed: true,
	}}
	if v := EvaluateVerdict(vs[0]); v.Verdict != VerdictAffected || v.FixedIn != "" {
		t.Fatalf("precondition: affected with no fix, got %+v", v)
	}
	ResolveUnverified(context.Background(), vs, fetcher(map[string]map[string]any{"CVE-2026-1": werkzeugRecord("3.1.9")}, &calls), 2)
	if v := EvaluateVerdict(vs[0]); v.Verdict != VerdictAffected || v.FixedIn != "3.1.9" {
		t.Errorf("should still be affected, now fixed in 3.1.9: %+v", v)
	}
}

// Learning where a fix landed must never clear a finding that is established.
func TestFixDetailLookupNeverClearsAnAffectedFinding(t *testing.T) {
	var calls int32
	vs := []EnrichedVuln{{
		VulnFinding:   VulnFinding{CveID: "CVE-2026-1", PackageName: "werkzeug", PackageVer: "3.1.0", Ecosystem: "pypi"},
		AffectedRange: "=3.1.0", VersionStatus: "affected", Confirmed: true,
	}}
	ResolveUnverified(context.Background(), vs, fetcher(map[string]map[string]any{"CVE-2026-1": werkzeugRecord("3.0.0")}, &calls), 2)
	if v := EvaluateVerdict(vs[0]); !v.Verdict.Counts() {
		t.Errorf("a record that disagrees must not hide the finding: %+v", v)
	}
}

func djangoRecord(entries ...map[string]any) map[string]any {
	vs := make([]any, len(entries))
	for i, e := range entries {
		vs[i] = e
	}
	return map[string]any{"identifier": "CVE-2019-14234",
		"affected": []any{map[string]any{"packageName": "Django", "ecosystem": "pypi", "versions": vs}}}
}

func rng(from, lessThan string) map[string]any {
	return map[string]any{"version": from, "lessThan": lessThan, "status": "affected", "versionType": "ECOSYSTEM"}
}

func djangoFinding(ver, rangeStr string) EnrichedVuln {
	return EnrichedVuln{
		VulnFinding:   VulnFinding{CveID: "CVE-2019-14234", PackageName: "Django", PackageVer: ver, Ecosystem: "pypi"},
		AffectedRange: rangeStr, VersionStatus: "affected", Confirmed: true,
	}
}

// A record that gives both "< 1.11.23" (introduced 0, a placeholder) and the
// bounded ">= 1.11.0 < 1.11.23" does not establish that 1.8.3 is affected: 1.8.3
// is older than every stated introduction. It is unverified, and still counts.
func TestOpenEndedRangeAloneDoesNotConfirmAVersionOlderThanEveryIntroduction(t *testing.T) {
	var calls int32
	rec := djangoRecord(rng("0", "1.11.23"), rng("1.11.0", "1.11.23"), rng("2.2.0", "2.2.4"))
	vs := []EnrichedVuln{djangoFinding("1.8.3", "=1.8.3")}
	ResolveUnverified(context.Background(), vs, fetcher(map[string]map[string]any{"CVE-2019-14234": rec}, &calls), 2)
	v := EvaluateVerdict(vs[0])
	if v.Verdict != VerdictUnverified || v.Basis != "conflict" || !v.Verdict.Counts() {
		t.Errorf("want unverified/conflict that still counts, got %+v", v)
	}
}

// Inside a bounded range it is affected, whatever else the record says.
func TestBoundedRangeStillConfirms(t *testing.T) {
	var calls int32
	rec := djangoRecord(rng("0", "1.11.23"), rng("1.11.0", "1.11.23"))
	vs := []EnrichedVuln{djangoFinding("1.11.5", "=1.11.5")}
	ResolveUnverified(context.Background(), vs, fetcher(map[string]map[string]any{"CVE-2019-14234": rec}, &calls), 2)
	if v := EvaluateVerdict(vs[0]); v.Verdict != VerdictAffected || v.FixedIn != "1.11.23" {
		t.Errorf("1.11.5 is inside >= 1.11.0 < 1.11.23: %+v", v)
	}
}

// With no bounded range in the record, introduced 0 is all there is, and it holds.
func TestOpenEndedRangeIsEnoughWhenItIsAllTheRecordHas(t *testing.T) {
	var calls int32
	vs := []EnrichedVuln{djangoFinding("1.8.3", "=1.8.3")}
	ResolveUnverified(context.Background(), vs, fetcher(map[string]map[string]any{"CVE-2019-14234": djangoRecord(rng("0", "1.11.23"))}, &calls), 2)
	if v := EvaluateVerdict(vs[0]); v.Verdict != VerdictAffected || v.FixedIn != "1.11.23" {
		t.Errorf("%+v", v)
	}
}

// A distribution rebuild's bound ("5.2.1+echo.1") says nothing about upstream.
func TestDistributionRebuildBoundsAreNotEvidence(t *testing.T) {
	var calls int32
	rec := djangoRecord(rng("0", "5.2.1+echo.1"), rng("4.2.0", "4.2.30"))
	vs := []EnrichedVuln{djangoFinding("1.8.3", "=1.8.3")}
	ResolveUnverified(context.Background(), vs, fetcher(map[string]map[string]any{"CVE-2019-14234": rec}, &calls), 2)
	if v := EvaluateVerdict(vs[0]); v.Verdict == VerdictAffected {
		t.Errorf("must not be confirmed by an +echo bound: %+v", v)
	}
}

// The scan response can itself carry the union "< 1.11.23 || >= 1.11.0 < 1.11.23".
// A version below the real introduction reaches it only through the open clause.
func TestRangeReachedOnlyThroughTheOpenClauseIsChecked(t *testing.T) {
	for _, tc := range []struct {
		rng, ver string
		want     bool
	}{
		{"< 1.11.23 || >= 1.11.0 < 1.11.23", "1.8.3", true},
		{"< 1.11.23 || >= 1.11.0 < 1.11.23", "1.11.5", false},
		{"< 1.11.23", "1.8.3", false},
		{">= 1.0.0 < 2.0.0", "1.5.0", false},
		{"< 3.1.6", "3.1.0", false},
	} {
		if got := reachedOnlyThroughOpenRange(tc.rng, tc.ver); got != tc.want {
			t.Errorf("reachedOnlyThroughOpenRange(%q, %q) = %v, want %v", tc.rng, tc.ver, got, tc.want)
		}
	}
	var calls int32
	rec := djangoRecord(rng("0", "1.11.23"), rng("1.11.0", "1.11.23"))
	vs := []EnrichedVuln{djangoFinding("1.8.3", "< 1.11.23 || >= 1.11.0 < 1.11.23")}
	if v := EvaluateVerdict(vs[0]); v.Verdict != VerdictAffected {
		t.Fatalf("precondition: %+v", v)
	}
	ResolveUnverified(context.Background(), vs, fetcher(map[string]map[string]any{"CVE-2019-14234": rec}, &calls), 2)
	if v := EvaluateVerdict(vs[0]); v.Verdict != VerdictUnverified || v.Basis != "conflict" {
		t.Errorf("%+v", v)
	}
}

// GHSA writes the open start as "*" rather than "0".
func TestWildcardStartCountsAsOpenEnded(t *testing.T) {
	var calls int32
	rec := djangoRecord(rng("*", "1.11.23"), rng("1.11a1", "1.11.23"), rng("2.2a1", "2.2.4"))
	vs := []EnrichedVuln{djangoFinding("1.8.3", "=1.8.3")}
	ResolveUnverified(context.Background(), vs, fetcher(map[string]map[string]any{"CVE-2019-14234": rec}, &calls), 2)
	if v := EvaluateVerdict(vs[0]); v.Verdict != VerdictUnverified || v.Basis != "conflict" {
		t.Errorf("%+v", v)
	}
}

// A gateway hiccup must not decide a verdict: a failed lookup is tried once more,
// and one that still fails is counted so the caller can say the pass was partial.
func TestAFailedLookupIsRetriedOnceAndCountedWhenItStaysFailed(t *testing.T) {
	var flaky int32
	fetch := func(_ context.Context, id, _, _ string) (map[string]any, error) {
		if id == "FLAKY" && atomic.AddInt32(&flaky, 1) == 1 {
			return nil, errors.New("API error (502): bad gateway")
		}
		if id == "DOWN" {
			return nil, errors.New("API error (502): bad gateway")
		}
		return pysec38(), nil
	}
	vs := []EnrichedVuln{fastapiFinding("FLAKY", "0.135.1"), fastapiFinding("DOWN", "0.135.1")}
	st := ResolveUnverified(context.Background(), vs, fetch, 2)
	if EvaluateVerdict(vs[0]).Verdict != VerdictNotAffected {
		t.Errorf("a one-off failure should be retried and settle: %+v", EvaluateVerdict(vs[0]))
	}
	if st.Failed != 1 {
		t.Errorf("Failed = %d, want 1 (the lookup that stayed down)", st.Failed)
	}
	if !EvaluateVerdict(vs[1]).Verdict.Counts() {
		t.Errorf("a finding whose lookup failed must keep counting")
	}
}
