package report

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vulnetix/cli/v3/internal/defences"
	"github.com/vulnetix/cli/v3/internal/scan"
)

var update = flag.Bool("update", false, "rewrite golden files")

// golden compares got with testdata/<name>.golden. Run with -update to rewrite.
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if string(want) != got {
		t.Errorf("%s differs from golden.\n--- got ---\n%s\n--- want ---\n%s", name, got, string(want))
	}
}

func meta() Meta {
	return Meta{ScannedPackages: 142, Manifests: 3, Kinds: []string{"sca", "sast"}, Elapsed: 4200 * time.Millisecond}
}

func rules(kinds ...defences.Kind) []defences.Rule {
	var out []defences.Rule
	for _, k := range kinds {
		out = append(out, defences.Rule{
			UUID: strings.ToLower(string(k)), ArtifactID: "X-" + string(k), Kind: k,
			Confidence: "HIGH", DeployMode: "log", FalsePositiveRisk: "LOW",
			CoverageNotes: "Matches the request shape in the public proof of concept. Does not match encoded or fragmented variants of it.",
			ExploitSource: "exploit-db", ArchiveURL: "/v2/x/" + strings.ToLower(string(k)) + "/archive",
		})
	}
	return out
}

func summaries() map[string]defences.Summary {
	return map[string]defences.Summary{
		"CVE-2025-11111": {State: defences.StateAvailable,
			Block:  defences.LaneSummary{Count: 2, ByKind: map[defences.Kind]int{defences.KindModSec: 1, defences.KindNginx: 1}, Rules: rules(defences.KindModSec, defences.KindNginx)},
			Detect: defences.LaneSummary{Count: 1, ByKind: map[defences.Kind]int{defences.KindSigma: 1}, Rules: rules(defences.KindSigma)}},
		"CVE-2025-22222": {State: defences.StateAvailable,
			Detect: defences.LaneSummary{Count: 1, ByKind: map[defences.Kind]int{defences.KindSigma: 1}, Rules: rules(defences.KindSigma)}},
		"CVE-2025-33333": {State: defences.StateGated,
			Block:  defences.LaneSummary{Count: 2, ByKind: map[defences.Kind]int{defences.KindSnort: 2}},
			Detect: defences.LaneSummary{Count: 1, ByKind: map[defences.Kind]int{defences.KindYARA: 1}}},
		"CVE-2025-44444": {State: defences.StateNone},
	}
}

func fullReport() Report {
	rep := Build(Input{Vulns: append(sampleVulns(), noFixVulns()...), Now: fixedNow, Meta: meta()})
	AttachDefences(&rep, summaries(), true, "")
	return rep
}

func pkg(t *testing.T, r Report, name string) Package {
	t.Helper()
	for _, p := range r.Packages {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("package %q not in report", name)
	return Package{}
}

func TestGoldenViews(t *testing.T) {
	rep := fullReport()
	golden(t, "packages_110", RenderPackages(rep, Options{}, plainTerm(110, true)))
	golden(t, "packages_80", RenderPackages(rep, Options{}, plainTerm(80, true)))
	golden(t, "packages_50", RenderPackages(rep, Options{}, plainTerm(50, true)))
	golden(t, "packages_ascii", RenderPackages(rep, Options{ASCII: true}, plainTerm(100, true)))
	golden(t, "plain", RenderPlain(rep, Options{}, plainTerm(100, false)))
	golden(t, "findings", RenderFindings(rep, Options{}, plainTerm(110, true)))
	golden(t, "tree", RenderTree(rep, Options{}, plainTerm(110, true)))
	golden(t, "github", RenderGitHub(rep))
	golden(t, "step_summary", StepSummary(rep))
	golden(t, "quiet", RenderPackages(rep, Options{Quiet: true}, plainTerm(110, true)))
}

func TestGoldenVerboseAndExplain(t *testing.T) {
	rep := fullReport()
	one := Report{Meta: rep.Meta, Packages: []Package{pkg(t, rep, "requests")}}
	golden(t, "verbose", RenderPackages(one, Options{Verbosity: 1}, plainTerm(110, true)))
	golden(t, "very_verbose", RenderPackages(one, Options{Verbosity: 2}, plainTerm(110, true)))

	out, ok := RenderExplain(rep, "PYSEC-2024-38", Options{}, plainTerm(100, true))
	if !ok {
		t.Fatal("explain found nothing")
	}
	golden(t, "explain_fastapi", out)

	out, ok = RenderExplain(rep, "legacy-xml", Options{}, plainTerm(100, true))
	if !ok {
		t.Fatal("explain by package found nothing")
	}
	golden(t, "explain_nofix", out)

	if _, ok := RenderExplain(rep, "no-such-thing", Options{}, plainTerm(100, true)); ok {
		t.Fatal("explain should report no match")
	}
}

func TestGoldenClean(t *testing.T) {
	rep := Build(Input{Meta: meta(), Now: fixedNow})
	golden(t, "clean_packages", RenderPackages(rep, Options{}, plainTerm(100, true)))
	golden(t, "clean_plain", RenderPlain(rep, Options{}, plainTerm(100, false)))
	if got := RenderPackages(rep, Options{Quiet: true}, plainTerm(100, true)); got != "" {
		t.Errorf("quiet on a clean scan must print nothing, got %q", got)
	}
}

// The kospex report. The finding is visible, labelled, and not counted.
func TestFastapiIsNotAFinding(t *testing.T) {
	rep := fullReport()
	p := pkg(t, rep, "fastapi")
	if p.Group != GroupNotAffected {
		t.Fatalf("fastapi group = %q, want not_affected", p.Group)
	}
	if len(p.Advisories) != 0 || len(p.RuledOut) != 1 {
		t.Fatalf("advisories=%d ruledOut=%d", len(p.Advisories), len(p.RuledOut))
	}
	c := rep.Counts()
	if c.Packages != 9 || c.Advisories != 15 {
		t.Errorf("counts = %d packages, %d advisories; fastapi must not be among them", c.Packages, c.Advisories)
	}

	strict := Build(Input{Vulns: sampleVulns(), Now: fixedNow, Strict: true})
	if g := pkg(t, strict, "fastapi").Group; g == GroupNotAffected {
		t.Error("--strict must count the finding")
	}
}

func TestGroupsPartitionCountedPackages(t *testing.T) {
	rep := fullReport()
	c := rep.Counts()
	sum := 0
	for _, g := range []Group{GroupAction, GroupWait, GroupUnverified, GroupProtected, GroupMonitored} {
		sum += c.ByGroup[g]
	}
	if sum != c.Packages {
		t.Fatalf("groups sum to %d, packages = %d: the header's counts must add up", sum, c.Packages)
	}
	for name, want := range map[string]Group{
		"log4j-core": GroupAction, "requests": GroupAction, "legacy-xml": GroupAction,
		"otherlib": GroupAction, "libexample": GroupAction,
		"pyyaml": GroupWait, "jinja2": GroupWait, "urllib3": GroupWait, "oldparser": GroupWait,
	} {
		if got := pkg(t, rep, name).Group; got != want {
			t.Errorf("%s: group %q, want %q", name, got, want)
		}
	}
}

func TestFixIsOneVersionThatClearsEverything(t *testing.T) {
	rep := fullReport()
	f := pkg(t, rep, "log4j-core").Fix
	if f.State != FixAvailable || f.Target != "2.17.1" || f.Clears != 4 {
		t.Errorf("log4j-core fix = %+v, want 2.17.1 clearing 4", f)
	}
	if f := pkg(t, rep, "legacy-xml").Fix; f.State != FixNone {
		t.Errorf("legacy-xml fix = %+v, want none", f)
	}

	partial := Build(Input{Now: fixedNow, Vulns: []scan.EnrichedVuln{
		vuln("CVE-1", "p", "1.0.0", "pypi", "high", "r.txt", withFix("1.2.0")),
		vuln("CVE-2", "p", "1.0.0", "pypi", "high", "r.txt", noFix()),
		vuln("CVE-3", "p", "1.0.0", "pypi", "high", "r.txt", withFix("1.1.0")),
	}})
	f = pkg(t, partial, "p").Fix
	if f.State != FixPartial || f.Target != "1.2.0" || f.Clears != 2 || f.Of != 3 {
		t.Errorf("partial fix = %+v", f)
	}
}

func TestSeverityIsNotUrgency(t *testing.T) {
	rep := fullReport()
	py := pkg(t, rep, "pyyaml")
	if py.Severity != "critical" || py.Group != GroupWait {
		t.Errorf("pyyaml: severity %q group %q: critical with no signal should wait", py.Severity, py.Group)
	}
}

func TestNotReachableIsOnlyClaimedWhenChecked(t *testing.T) {
	rep := Build(Input{Now: fixedNow, Vulns: []scan.EnrichedVuln{
		vuln("CVE-1", "a", "1.0.0", "pypi", "high", "r.txt", withFix("2.0.0")), // never assessed
	}})
	if out := RenderPackages(rep, Options{}, plainTerm(110, true)); strings.Contains(out, "not reachable") {
		t.Errorf("claimed not reachable without having checked:\n%s", out)
	}
	rep = Build(Input{Now: fixedNow, Vulns: []scan.EnrichedVuln{
		vuln("CVE-1", "a", "1.0.0", "pypi", "high", "r.txt", withFix("2.0.0"), assessed()),
	}})
	if out := RenderPackages(rep, Options{}, plainTerm(110, true)); !strings.Contains(out, "not reachable") {
		t.Errorf("should say not reachable when it was assessed:\n%s", out)
	}
}

func TestFilters(t *testing.T) {
	rep := fullReport()
	names := func(r Report) []string {
		var out []string
		for _, p := range r.Packages {
			out = append(out, p.Name)
		}
		return out
	}
	cases := []struct {
		filters []string
		want    []string
	}{
		{[]string{"kev"}, []string{"log4j-core", "otherlib"}},
		{[]string{"nofix"}, []string{"legacy-xml", "libexample", "otherlib", "oldparser"}},
		{[]string{"nofix", "kev"}, []string{"otherlib"}},
		{[]string{"reachable"}, []string{"log4j-core"}},
	}
	for _, c := range cases {
		got := names(Apply(rep, Options{Filters: c.filters}))
		if strings.Join(sortedCopy(got), ",") != strings.Join(sortedCopy(c.want), ",") {
			t.Errorf("--filter %v = %v, want %v", c.filters, got, c.want)
		}
	}
	if got := names(Apply(rep, Options{MinSeverity: "critical"})); len(got) == 0 {
		t.Error("min-severity critical removed everything")
	} else {
		for _, p := range Apply(rep, Options{MinSeverity: "critical"}).Packages {
			if p.Group != GroupNotAffected && p.Severity != "critical" {
				t.Errorf("%s (%s) survived --min-severity critical", p.Name, p.Severity)
			}
		}
	}
	if err := Validate("filter", []string{"kev", "bogus"}, FilterNames); err == nil || !strings.Contains(err.Error(), "bogus") || !strings.Contains(err.Error(), "unprotected") {
		t.Errorf("validation error should name the bad value and list the valid ones: %v", err)
	}
}

func sortedCopy(in []string) []string {
	out := append([]string{}, in...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func TestControlsMoveFindingsAndExpire(t *testing.T) {
	ctl := func(lane defences.Lane, mode string, until time.Time) defences.ControlSet {
		return defences.ControlSet{Controls: []defences.Control{{
			VulnID: "CVE-2025-11111", Package: "legacy-xml", Lane: lane, Mode: mode,
			Where: "ModSecurity, prod-eu ingress", RecordedAt: fixedNow, Until: until,
		}}}
	}
	build := func(c defences.ControlSet) Package {
		rep := Build(Input{Vulns: noFixVulns(), Controls: c, Now: fixedNow})
		return pkg(t, rep, "legacy-xml")
	}

	if g := build(ctl(defences.LaneBlock, "block", fixedNow.Add(24*time.Hour))).Group; g != GroupProtected {
		t.Errorf("a live blocking control: group %q, want protected", g)
	}
	if g := build(ctl(defences.LaneBlock, "log", fixedNow.Add(24*time.Hour))).Group; g != GroupMonitored {
		t.Errorf("a log-only rule blocks nothing: group %q, want monitored", g)
	}
	if g := build(ctl(defences.LaneDetect, "", fixedNow.Add(24*time.Hour))).Group; g != GroupMonitored {
		t.Errorf("a detection stops nothing: group %q, want monitored", g)
	}
	lapsed := build(ctl(defences.LaneBlock, "block", fixedNow.Add(-time.Hour)))
	if lapsed.Group != GroupAction || lapsed.Lapsed == nil {
		t.Errorf("an expired control must return the finding to action and say so: group %q lapsed=%v", lapsed.Group, lapsed.Lapsed)
	}
	if !strings.Contains(RenderPackages(Report{Packages: []Package{lapsed}}, Options{}, plainTerm(100, true)), "control expired") {
		t.Error("the expiry should be stated")
	}

	// A protected finding is still counted: it is not hidden.
	rep := Build(Input{Vulns: noFixVulns(), Now: fixedNow,
		Controls: ctl(defences.LaneBlock, "block", fixedNow.Add(24*time.Hour))})
	if got := rep.Counts().ByGroup[GroupProtected]; got != 1 {
		t.Errorf("protected = %d", got)
	}
	if n := len(Unprotected(rep)); n != 3 {
		t.Errorf("unprotected no-fix packages = %d, want 3 (the other three)", n)
	}
	golden(t, "protected", RenderPackages(rep, Options{}, plainTerm(100, true)))
}

func TestDefenceStates(t *testing.T) {
	rep := Build(Input{Vulns: append(noFixVulns(),
		vuln("NOT AN ID", "pyonly", "1.0.0", "pypi", "high", "r.txt", noFix())), Now: fixedNow})
	for _, state := range []struct {
		name    string
		attach  func(*Report)
		want    string
		notWant string
	}{
		{"unavailable stays silent", func(r *Report) {
			AttachDefences(r, map[string]defences.Summary{
				"CVE-2025-11111": {State: defences.StateUnavailable},
				"CVE-2025-22222": {State: defences.StateUnavailable},
				"CVE-2025-33333": {State: defences.StateUnavailable},
				"CVE-2025-44444": {State: defences.StateUnavailable},
			}, true, "")
		}, "", "defence lookup"},
		{"not checked says so", func(r *Report) { AttachDefences(r, nil, false, "offline") }, "not checked (offline)", ""},
		{"failed says so", func(r *Report) { AttachDefences(r, nil, true, "timeout") }, "lookup failed (timeout)", ""},
	} {
		t.Run(state.name, func(t *testing.T) {
			r := rep
			r.Packages = append([]Package{}, rep.Packages...)
			state.attach(&r)
			out := RenderPackages(r, Options{}, plainTerm(110, true))
			if state.want != "" && !strings.Contains(out, state.want) {
				t.Errorf("missing %q in:\n%s", state.want, out)
			}
			if state.notWant != "" && strings.Contains(out, state.notWant) {
				t.Errorf("unexpected %q in:\n%s", state.notWant, out)
			}
		})
	}

	// A finding whose identifier is not shaped like an advisory id cannot be looked up, and says so.
	r := rep
	r.Packages = append([]Package{}, rep.Packages...)
	AttachDefences(&r, summaries(), true, "")
	if out := RenderPackages(r, Options{}, plainTerm(110, true)); !strings.Contains(out, "not indexed: NOT AN ID is not an advisory identifier the database can look up") {
		t.Errorf("the not-indexed state is missing:\n%s", out)
	}

	// Findings with a fix never get a defence block.
	full := fullReport()
	if pkg(t, full, "requests").Defence != nil {
		t.Error("a package with a fix must not look up defences")
	}
	if got := DefenceIDs(full); len(got) != 4 {
		t.Errorf("DefenceIDs = %v, want the four no-fix advisories", got)
	}
}

func TestHideDefencesAndFixes(t *testing.T) {
	rep := fullReport()
	out := RenderPackages(rep, Options{Hide: map[string]bool{"defences": true, "fixes": true}}, plainTerm(110, true))
	if strings.Contains(out, "◆") || strings.Contains(out, "no fix") || strings.Contains(out, "→ 2.17.1") {
		t.Errorf("hidden parts leaked:\n%s", out)
	}
}

func TestResolveView(t *testing.T) {
	tty, pipe := plainTerm(100, true), plainTerm(100, false)
	for _, c := range []struct {
		o    Options
		t    interface{}
		ci   bool
		want string
	}{
		{Options{}, tty, false, ViewPackages},
		{Options{}, pipe, false, ViewPlain},
		{Options{}, tty, true, ViewPlain},
		{Options{View: ViewFindings}, pipe, true, ViewFindings},
		{Options{View: ViewAuto}, tty, false, ViewPackages},
	} {
		term := tty
		if c.t == interface{}(pipe) {
			term = pipe
		}
		if got := ResolveView(c.o, term, c.ci); got != c.want {
			t.Errorf("ResolveView(%+v, tty=%v, ci=%v) = %q, want %q", c.o, term.IsTTY, c.ci, got, c.want)
		}
	}
}

// Nothing the renderers print may be wider than the terminal they were given,
// except a path or id that cannot be shortened.
func TestNoLineExceedsWidthByMuch(t *testing.T) {
	rep := fullReport()
	for _, w := range []int{50, 80, 110} {
		for _, line := range strings.Split(RenderPackages(rep, Options{}, plainTerm(w, true)), "\n") {
			if n := len([]rune(line)); n > w+2 {
				t.Errorf("width %d: line is %d wide: %q", w, n, line)
			}
		}
	}
}

// The live fastapi record: every advisory's range is a git commit. The package
// is real, so it counts, but nothing established it is affected, so it must not
// sit under NEEDS ACTION on the strength of a PoC attached to an advisory that
// may not apply.
func TestUnverifiedDoesNotClaimUrgency(t *testing.T) {
	commit := withRange("<9d34ad0ee8a0dfbbcce06f76c2d5d851085024fc")
	rep := Build(Input{Now: fixedNow, Vulns: []scan.EnrichedVuln{
		vuln("CVE-2024-24762", "fastapi", "0.135.1", "pypi", "critical", "requirements.txt", commit, exploit(2, true), kev()),
		vuln("PYSEC-2024-38", "fastapi", "0.135.1", "pypi", "high", "requirements.txt", commit),
		vuln("CVE-2018-18074", "requests", "2.19.1", "pypi", "high", "requirements.txt", withRange("< 2.20.0"), exploit(1, false)),
	}})
	fa := pkg(t, rep, "fastapi")
	if fa.Group != GroupUnverified {
		t.Fatalf("fastapi group = %q, want unverified", fa.Group)
	}
	if got := rep.Counts().Packages; got != 2 {
		t.Errorf("an unverified package still counts: packages = %d, want 2", got)
	}
	if g := pkg(t, rep, "requests").Group; g != GroupAction {
		t.Errorf("requests (range-checked, PoC) group = %q, want action", g)
	}
	out := RenderPackages(rep, Options{}, plainTerm(110, true))
	for _, want := range []string{"UNVERIFIED", "matched by name, version could not be checked", "? unverified", "1 unverified"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	golden(t, "unverified", out)

	exp, _ := RenderExplain(rep, "PYSEC-2024-38", Options{}, plainTerm(100, true))
	if !strings.Contains(exp, "git commit (9d34ad0)") {
		t.Errorf("explain should say why the range cannot be checked:\n%s", exp)
	}
	golden(t, "explain_unverified", exp)
}

// A package whose advisories have ranges with an upper bound gets its fix from
// the range, even when the server's flag says no_fix.
func TestFixComesFromTheAdvisoryRange(t *testing.T) {
	rep := Build(Input{Now: fixedNow, Vulns: []scan.EnrichedVuln{
		vuln("GHSA-1", "requests", "2.19.1", "pypi", "high", "r.txt", withRange("< 2.32.4"), noFix()),
		vuln("PYSEC-2", "requests", "2.19.1", "pypi", "high", "r.txt", withRange("= 2.19.1"), noFix()),
	}})
	f := pkg(t, rep, "requests").Fix
	if f.State != FixAvailable || f.Target != "2.32.4" || f.Of != 2 {
		t.Errorf("fix = %+v, want 2.32.4 clearing both (an exact-version advisory is cleared by any upgrade)", f)
	}
}

// Advisories that clear on "any newer release" name no version to move to. With
// others explicitly unfixed, "partly fixed" points nowhere and hid the defences.
func TestPartialFixWithNoVersionToMoveToIsNoFix(t *testing.T) {
	p := Package{Advisories: []Advisory{
		{ID: "A", AnyUpgrade: true},
		{ID: "B", AnyUpgrade: true},
		{ID: "C", FixAvailability: "no_fix"},
		{ID: "D", FixAvailability: "no_fix"},
	}}
	if got := computeFix(p); got.State != FixNone {
		t.Errorf("want no fix, got %+v", got)
	}
	p.Advisories[0].Fix = "2.0.0"
	if got := computeFix(p); got.State != FixPartial || got.Target != "2.0.0" {
		t.Errorf("a concrete version keeps it partial: %+v", got)
	}
}

// A lookup that failed after retries leaves the answer incomplete. "Nothing found"
// must not read as "clean": that is the one claim a user would act on.
func TestIncompleteLookupIsNeverReportedClean(t *testing.T) {
	r := Report{Meta: Meta{ScannedPackages: 40, Unchecked: []string{"pkg:pypi/a@1", "pkg:pypi/b@2"}}}
	plain := RenderPlain(r, Options{Command: "scan"}, nil)
	if strings.Contains(plain, "CLEAN") || !strings.Contains(plain, "INCOMPLETE") {
		t.Fatalf("plain view must say INCOMPLETE, got:\n%s", plain)
	}
	if !strings.Contains(plain, "2 packages") {
		t.Errorf("the count of unchecked packages is missing:\n%s", plain)
	}
	js, err := RenderJSON(r)
	if err != nil || !strings.Contains(string(js), `"unchecked"`) {
		t.Fatalf("JSON meta must list the unchecked packages: %v\n%s", err, js)
	}
	clean := RenderPlain(Report{Meta: Meta{ScannedPackages: 40}}, Options{Command: "scan"}, nil)
	if !strings.Contains(clean, "CLEAN") {
		t.Errorf("a complete lookup with no findings is still clean:\n%s", clean)
	}
}
