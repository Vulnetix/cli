package cmd

// Pretty terminal rendering for `malscan` — the default output when no -o format
// is given. The drawing is internal/report's, like every other scanner's; this
// file only maps the scan's result onto it.

import (
	"fmt"
	"os"
	"strings"

	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/report"
)

func malscanReportFrom(res *malscanResult) report.MalscanReport {
	m := report.MalscanReport{
		Indicators:   res.IndicatorCount,
		FeedsEnabled: res.FeedsEnabled,
		IncludeHome:  res.IncludeHome,
		Warnings:     res.Warnings,
	}
	// The feeds name ecosystems by package manager (npm, pypi, go); findings carry
	// the human label (javascript), so the report speaks the first throughout.
	slug := map[string]string{}
	for _, c := range res.Checked {
		slug[c.Target.Ecosystem] = c.Target.EngineSlug
	}
	name := func(label string) string {
		if s := slug[label]; s != "" {
			return s
		}
		return label
	}
	for _, c := range res.Checked {
		m.Targets = append(m.Targets, report.MalscanTarget{
			Ecosystem: name(c.Target.Ecosystem), Label: c.Target.Label, UserScoped: c.Target.UserScoped,
			Packages: c.Packages, Files: c.Files,
		})
	}
	for _, f := range res.Findings {
		m.Findings = append(m.Findings, report.MalscanFinding{
			Ecosystem: name(f.Ecosystem), Package: f.Package, Location: f.Location,
			Title: findingTitle(f), RuleID: f.RuleID, File: f.File, Line: f.StartLine, Snippet: f.Snippet,
			Severity: f.Severity, Class: f.Class, IOCType: f.IOCType, IOCValue: f.IOCValue,
		})
	}
	return m
}

func renderMalscanPretty(res *malscanResult) {
	o := report.Options{Command: "malscan"}
	if verbose {
		o.Verbosity = 1
	}
	fmt.Fprint(os.Stdout, report.RenderMalscan(malscanReportFrom(res), o, display.NewTerminal()))
}

// findingTitle is what a row says is wrong. The rule's description reads as a
// sentence ("Download-and-execute in install script"); the category is only a
// bucket ("install"), so it is the fallback.
func findingTitle(f malscanFinding) string {
	if d := strings.TrimSpace(f.Description); d != "" && f.RuleID != "IOC-STIX-MATCH" {
		first, _, _ := strings.Cut(d, "\n")
		return first
	}
	return f.Title
}
