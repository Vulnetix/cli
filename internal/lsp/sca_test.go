package lsp

import (
	"strings"
	"testing"

	"github.com/vulnetix/cli/v3/internal/lsp/protocol"
	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// The fixture manifest, byte-for-byte from the extension's test workspace, so
// the line numbers asserted here are the ones a user would see.
const fixturePackageJSON = `{
  "name": "vulnetix-fixture-app",
  "version": "1.0.0",
  "private": true,
  "description": "Intentionally vulnerable fixture. Do not deploy.",
  "license": "AGPL-3.0-only",
  "scripts": {
    "start": "node src/vuln.js"
  },
  "dependencies": {
    "lodash": "4.17.20",
    "minimist": "0.0.8",
    "express": "4.16.0"
  }
}`

func vuln(cve, severity string, kev bool) scan.EnrichedVuln {
	v := scan.EnrichedVuln{MaxSeverity: severity}
	v.CveID = cve
	v.InCisaKev = kev
	return v
}

// seedEngine builds an engine with a known dependency picture and no network.
func seedEngine(t *testing.T) *scaEngine {
	t.Helper()

	e := newSCAEngine("test", nil)
	e.root = "/repo"
	e.packagesByFile = map[string][]scan.ScopedPackage{
		"package.json": {
			{Name: "lodash", Version: "4.17.20", Ecosystem: "npm", SourceFile: "package.json", IsDirect: true},
			{Name: "minimist", Version: "0.0.8", Ecosystem: "npm", SourceFile: "package.json", IsDirect: true},
			{Name: "express", Version: "4.16.0", Ecosystem: "npm", SourceFile: "package.json", IsDirect: true},
		},
	}
	e.typeByFile = map[string]string{"package.json": "package.json"}
	e.verdicts = map[string]*scaVerdict{
		"pkg:npm/lodash@4.17.20": {
			Purl: "pkg:npm/lodash@4.17.20", Name: "lodash", Version: "4.17.20",
			Ecosystem: "npm", SourceFile: "package.json", IsDirect: true,
			Vulns: []scan.EnrichedVuln{
				vuln("CVE-2021-23337", "critical", false),
				vuln("CVE-2020-8203", "critical", false),
				vuln("CVE-2019-10744", "high", false),
				vuln("CVE-2020-28500", "high", false),
				vuln("CVE-2018-16487", "high", false),
				vuln("CVE-2018-3721", "medium", false),
				vuln("CVE-2018-3741", "low", false),
			},
		},
		"pkg:npm/minimist@0.0.8": {
			Purl: "pkg:npm/minimist@0.0.8", Name: "minimist", Version: "0.0.8",
			Ecosystem: "npm", SourceFile: "package.json", IsDirect: true,
			Vulns: []scan.EnrichedVuln{vuln("CVE-2020-7598", "medium", false)},
		},
		// express is clean, which is what earns it the quiet marker.
		"pkg:npm/express@4.16.0": {
			Purl: "pkg:npm/express@4.16.0", Name: "express", Version: "4.16.0",
			Ecosystem: "npm", SourceFile: "package.json", IsDirect: true,
		},
	}
	e.scanned = true
	return e
}

// resolveSafeVersions simulates phase two completing for one package.
func resolveSafeVersions(e *scaEngine, purl string, insight *vdb.CliPackageInsight) {
	v := e.verdicts[purl]
	v.Insight = insight
	v.SafeState = safeResolved
}

func lodashInsight() *vdb.CliPackageInsight {
	return &vdb.CliPackageInsight{
		Purl:      "pkg:npm/lodash@4.17.20",
		Name:      "lodash",
		Version:   "4.17.20",
		Ecosystem: "npm",
		SafeVersions: []vdb.CliSafeHarbourVersion{
			{Version: "4.17.21", VulnerabilityCount: 0, SafeHarbourScore: 98},
			{Version: "4.17.20", VulnerabilityCount: 7, SafeHarbourScore: 10},
		},
		SafeHarbour: &vdb.CliSafeHarbourSummary{
			RecommendedVersions: []string{"4.17.21"},
			Recommendation:      &vdb.CliSafeHarbourRecommendation{Version: "4.17.21"},
		},
	}
}

func TestSCADiagnosticsAnchorOnTheDeclarationLine(t *testing.T) {
	e := seedEngine(t)
	diags := e.SCADiagnostics("package.json", fixturePackageJSON, SeverityMapping{})

	if len(diags) != 2 {
		t.Fatalf("got %d diagnostics, want 2 (lodash and minimist; express is clean)", len(diags))
	}

	// Zero-based line 10 is the 1-based line 11 the fixture pins for lodash.
	if diags[0].Range.Start.Line != 10 {
		t.Errorf("lodash anchored at line %d, want 10 (0-based)", diags[0].Range.Start.Line)
	}
	if diags[1].Range.Start.Line != 11 {
		t.Errorf("minimist anchored at line %d, want 11 (0-based)", diags[1].Range.Start.Line)
	}
}

// The source string is what routes a finding into the dependency collection.
// Anything else is silently filed as a code finding by the extension.
func TestSCADiagnosticsUseTheDependencySource(t *testing.T) {
	e := seedEngine(t)
	for _, d := range e.SCADiagnostics("package.json", fixturePackageJSON, SeverityMapping{}) {
		if d.Source != "vulnetix-sca" {
			t.Errorf("source = %q, want vulnetix-sca", d.Source)
		}
	}
}

func TestSCADiagnosticMessageMatchesTheDesignedSummary(t *testing.T) {
	e := seedEngine(t)
	diags := e.SCADiagnostics("package.json", fixturePackageJSON, SeverityMapping{})

	got := diags[0].Message
	for _, want := range []string{"lodash@4.17.20", "7 vulnerabilities", "2 critical", "3 high"} {
		if !strings.Contains(got, want) {
			t.Errorf("message %q is missing %q", got, want)
		}
	}
	if diags[0].Severity != protocol.SeverityError {
		t.Errorf("severity = %d, want Error for a critical finding", diags[0].Severity)
	}
	if diags[0].Code != "CVE-2021-23337" {
		t.Errorf("code = %q, want the most severe advisory", diags[0].Code)
	}
	if diags[0].CodeDescription == nil {
		t.Error("a CVE code should carry a link")
	}
}

// A quick fix cannot be offered before Safe-Harbour has answered. Offering one
// built on nothing would put an arbitrary version in the user's manifest.
func TestCodeActionsRequireResolvedSafeVersions(t *testing.T) {
	e := seedEngine(t)
	whole := protocol.Range{End: protocol.Position{Line: 100}}

	if got := e.CodeActions("package.json", fixturePackageJSON, "file:///repo/package.json", whole); len(got) != 0 {
		t.Fatalf("got %d actions before phase two, want 0", len(got))
	}

	resolveSafeVersions(e, "pkg:npm/lodash@4.17.20", lodashInsight())

	actions := e.CodeActions("package.json", fixturePackageJSON, "file:///repo/package.json", whole)
	if len(actions) == 0 {
		t.Fatal("no actions after safe versions resolved")
	}
	if !strings.Contains(actions[0].Title, "4.17.21") {
		t.Errorf("title = %q, want the bump to 4.17.21", actions[0].Title)
	}
	if !actions[0].IsPreferred {
		t.Error("the recommended target should be the preferred action")
	}
}

// The edit has to produce the text the CLI would have written, and touch only
// the line that changed.
func TestCodeActionEditRewritesOnlyTheDependencyLine(t *testing.T) {
	e := seedEngine(t)
	resolveSafeVersions(e, "pkg:npm/lodash@4.17.20", lodashInsight())

	uri := "file:///repo/package.json"
	actions := e.CodeActions("package.json", fixturePackageJSON, uri,
		protocol.Range{End: protocol.Position{Line: 100}})

	edits := actions[0].Edit.Changes[uri]
	if len(edits) != 1 {
		t.Fatalf("got %d edits, want 1", len(edits))
	}
	if !strings.Contains(edits[0].NewText, "4.17.21") {
		t.Errorf("edit text %q does not contain the target version", edits[0].NewText)
	}
	if strings.Contains(edits[0].NewText, "minimist") {
		t.Errorf("edit spans unrelated lines: %q", edits[0].NewText)
	}
	if edits[0].Range.Start.Line != 10 {
		t.Errorf("edit starts at line %d, want 10", edits[0].Range.Start.Line)
	}
}

// A malicious package is never offered as a fix target, whatever its rank.
func TestCodeActionsSkipMalwareVersions(t *testing.T) {
	e := seedEngine(t)
	resolveSafeVersions(e, "pkg:npm/lodash@4.17.20", &vdb.CliPackageInsight{
		Purl: "pkg:npm/lodash@4.17.20",
		SafeVersions: []vdb.CliSafeHarbourVersion{
			{Version: "4.17.99", VulnerabilityCount: 0, IsMalware: true},
		},
		SafeHarbour: &vdb.CliSafeHarbourSummary{
			Recommendation: &vdb.CliSafeHarbourRecommendation{Version: "4.17.99"},
		},
	})

	for _, a := range e.CodeActions("package.json", fixturePackageJSON, "file:///repo/package.json",
		protocol.Range{End: protocol.Position{Line: 100}}) {
		if strings.Contains(a.Title, "4.17.99") {
			t.Errorf("offered a version flagged as malware: %q", a.Title)
		}
	}
}

// The three inline states are what make "checked and clean" distinguishable
// from "not looked at".
func TestInlayHintsRenderTheThreeStates(t *testing.T) {
	e := seedEngine(t)
	whole := protocol.Range{End: protocol.Position{Line: 100}}

	byLine := map[int]string{}
	for _, h := range e.InlayHints("package.json", fixturePackageJSON, whole) {
		byLine[h.Position.Line] = h.Label
	}

	if byLine[12] != hintChecked {
		t.Errorf("express (line 12) = %q, want the checked marker", byLine[12])
	}

	e.verdicts["pkg:npm/lodash@4.17.20"].SafeState = safePending
	byLine = map[int]string{}
	for _, h := range e.InlayHints("package.json", fixturePackageJSON, whole) {
		byLine[h.Position.Line] = h.Label
	}
	if byLine[10] != hintPending {
		t.Errorf("lodash (line 10) = %q, want the pending marker", byLine[10])
	}

	resolveSafeVersions(e, "pkg:npm/lodash@4.17.20", lodashInsight())
	byLine = map[int]string{}
	for _, h := range e.InlayHints("package.json", fixturePackageJSON, whole) {
		byLine[h.Position.Line] = h.Label
	}
	if byLine[10] != "→ 4.17.21" {
		t.Errorf("lodash (line 10) = %q, want the resolved target", byLine[10])
	}
}

// Before the bulk pass nothing is known, and a checkmark would be a lie.
func TestInlayHintsSilentBeforeFirstScan(t *testing.T) {
	e := seedEngine(t)
	e.scanned = false

	if got := e.InlayHints("package.json", fixturePackageJSON,
		protocol.Range{End: protocol.Position{Line: 100}}); len(got) != 0 {
		t.Errorf("got %d hints before the first scan, want none", len(got))
	}
}

func TestHoverRendersTheDependencyCard(t *testing.T) {
	e := seedEngine(t)
	resolveSafeVersions(e, "pkg:npm/lodash@4.17.20", lodashInsight())

	h := e.Hover("package.json", fixturePackageJSON, protocol.Position{Line: 10, Character: 6})
	if h == nil {
		t.Fatal("no hover on the lodash line")
	}
	for _, want := range []string{"lodash@4.17.20", "7 vulnerabilities", "CVE-2021-23337", "4.17.21"} {
		if !strings.Contains(h.Contents.Value, want) {
			t.Errorf("hover is missing %q:\n%s", want, h.Contents.Value)
		}
	}
}

func TestHoverIsNilOffADependency(t *testing.T) {
	e := seedEngine(t)
	if h := e.Hover("package.json", fixturePackageJSON, protocol.Position{Line: 1}); h != nil {
		t.Errorf("hover on the name field should be nil, got:\n%s", h.Contents.Value)
	}
}

func TestSCADisabledProducesNothing(t *testing.T) {
	e := seedEngine(t)
	e.cfg.Enabled = false

	if got := e.SCADiagnostics("package.json", fixturePackageJSON, SeverityMapping{}); len(got) != 0 {
		t.Errorf("got %d diagnostics with SCA off", len(got))
	}
	if got := e.Hover("package.json", fixturePackageJSON, protocol.Position{Line: 10}); got != nil {
		t.Error("hover answered with SCA off")
	}
}

func TestChunkStrings(t *testing.T) {
	in := []string{"a", "b", "c", "d", "e"}
	got := chunkStrings(in, 2)
	if len(got) != 3 || len(got[2]) != 1 {
		t.Fatalf("chunkStrings = %v", got)
	}
	if len(chunkStrings(nil, 25)) != 0 {
		t.Error("no purls should produce no chunks")
	}
}

// The server reports per-feature gating, and an absence caused by it is a
// different statement from an absence caused by there being nothing to report.
func TestGatedSafeVersionsAreExplainedNotDenied(t *testing.T) {
	e := seedEngine(t)
	e.gated = map[string]bool{featureSafeVersions: true}
	resolveSafeVersions(e, "pkg:npm/lodash@4.17.20", &vdb.CliPackageInsight{
		Purl: "pkg:npm/lodash@4.17.20",
	})

	h := e.Hover("package.json", fixturePackageJSON, protocol.Position{Line: 10})
	if h == nil {
		t.Fatal("no hover")
	}
	if !strings.Contains(h.Contents.Value, "Pro unlocks Safe-Harbour") {
		t.Errorf("a gated feature should be explained, not reported as absent:\n%s", h.Contents.Value)
	}
	if strings.Contains(h.Contents.Value, "none available") {
		t.Errorf("a gated feature must not be reported as no fix existing:\n%s", h.Contents.Value)
	}

	// And no inline marker, which would either spin forever or invent a target.
	for _, hint := range e.InlayHints("package.json", fixturePackageJSON,
		protocol.Range{End: protocol.Position{Line: 100}}) {
		if hint.Position.Line == 10 {
			t.Errorf("gated package should carry no marker, got %q", hint.Label)
		}
	}
}

// Exploit data does reach the community tier, so the upsell must be driven by
// what the server withheld rather than by the plan name.
func TestExploitSectionFollowsServerGating(t *testing.T) {
	e := seedEngine(t)
	e.tier = "community"

	// Not gated and none found: say so plainly.
	h := e.Hover("package.json", fixturePackageJSON, protocol.Position{Line: 10})
	if !strings.Contains(h.Contents.Value, "none known") {
		t.Errorf("ungated and empty should read as none known:\n%s", h.Contents.Value)
	}

	e.gated = map[string]bool{featureExploits: true}
	h = e.Hover("package.json", fixturePackageJSON, protocol.Position{Line: 10})
	if !strings.Contains(h.Contents.Value, "Pro unlocks exploit intel") {
		t.Errorf("gated exploits should be explained:\n%s", h.Contents.Value)
	}
	if strings.Contains(h.Contents.Value, "none known") {
		t.Errorf("gated exploits must not read as none known:\n%s", h.Contents.Value)
	}
}

// A package declared in both a manifest and its lockfile is one package.
// SynthesiseFromCDX emits a finding per declaration, so without deduplication a
// package with twelve advisories is reported as having twenty-four, and every
// exploit count on the hover card doubles.
func TestBulkGroupingCountsEachAdvisoryOnce(t *testing.T) {
	duplicated := []scan.EnrichedVuln{
		vuln("CVE-2021-23337", "critical", false),
		vuln("CVE-2021-23337", "critical", false),
		vuln("CVE-2020-8203", "high", false),
		vuln("CVE-2020-8203", "high", false),
	}

	byPurl := map[string][]scan.EnrichedVuln{}
	seen := map[string]bool{}
	for _, v := range duplicated {
		key := "pkg:npm/lodash@4.17.20\x00" + v.CveID
		if seen[key] {
			continue
		}
		seen[key] = true
		byPurl["pkg:npm/lodash@4.17.20"] = append(byPurl["pkg:npm/lodash@4.17.20"], v)
	}

	if got := len(byPurl["pkg:npm/lodash@4.17.20"]); got != 2 {
		t.Fatalf("got %d advisories, want 2 distinct", got)
	}

	// And the rendered message reflects the distinct count.
	e := seedEngine(t)
	e.verdicts["pkg:npm/lodash@4.17.20"].Vulns = byPurl["pkg:npm/lodash@4.17.20"]

	diags := e.SCADiagnostics("package.json", fixturePackageJSON, SeverityMapping{})
	if !strings.Contains(diags[0].Message, "2 vulnerabilities") {
		t.Errorf("message should count distinct advisories: %q", diags[0].Message)
	}
}
