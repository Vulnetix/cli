package cmd

// Pretty terminal rendering for `malscan` — the default output when no -o format
// is given. Mirrors the table style used by aibom/scan.

import (
	"fmt"
	"strings"

	"github.com/vulnetix/cli/v3/internal/display"
)

func renderMalscanPretty(res *malscanResult) {
	t := display.NewTerminal()
	var b strings.Builder

	b.WriteString(display.Header(t, "Malware Scan"))
	b.WriteByte('\n')
	fmt.Fprintf(&b, "  %d target(s) scanned, %d file(s) inspected, %d known-bad indicator(s) loaded\n\n",
		len(res.Targets), res.FilesScanned, res.IndicatorCount)

	if len(res.Targets) > 0 {
		rows := make([][]string, 0, len(res.Targets))
		for _, tg := range res.Targets {
			scope := "project"
			if tg.UserScoped {
				scope = "home"
			}
			rows = append(rows, []string{tg.Ecosystem, tg.EngineSlug, scope, tg.Label})
		}
		b.WriteString(display.Header(t, "Scan Targets"))
		b.WriteByte('\n')
		b.WriteString(display.Table(t, []display.Column{
			{Header: "Ecosystem"}, {Header: "Feed"}, {Header: "Scope"}, {Header: "Location"},
		}, rows))
		b.WriteString("\n\n")
	}

	if len(res.Findings) > 0 {
		b.WriteString(display.Header(t, "Findings"))
		b.WriteByte('\n')
		rows := make([][]string, 0, len(res.Findings))
		for _, f := range res.Findings {
			loc := f.File
			if f.StartLine > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.StartLine)
			}
			rows = append(rows, []string{f.Severity, f.RuleID, f.Class, f.Ecosystem, loc})
		}
		b.WriteString(display.Table(t, []display.Column{
			{Header: "Severity"}, {Header: "Rule"}, {Header: "Class"}, {Header: "Ecosystem"}, {Header: "Location"},
		}, rows))
		b.WriteString("\n\n")
	}

	if len(res.IOCs) > 0 {
		b.WriteString(display.Header(t, "Indicators of Compromise"))
		b.WriteByte('\n')
		rows := make([][]string, 0, len(res.IOCs))
		for _, i := range res.IOCs {
			sample := ""
			if i.Sample != nil {
				sample = i.Sample.SHA256[:min(12, len(i.Sample.SHA256))]
			}
			rows = append(rows, []string{i.Type, truncateCmd(i.Value, 48), i.Ecosystem, i.FilePath, sample})
		}
		b.WriteString(display.Table(t, []display.Column{
			{Header: "Type"}, {Header: "Value"}, {Header: "Ecosystem"}, {Header: "File"}, {Header: "Sample"},
		}, rows))
		b.WriteString("\n\n")
	}

	if len(res.Findings) == 0 {
		b.WriteString("  No malware detected.\n\n")
	} else {
		fmt.Fprintf(&b, "  %s detected — see .vulnetix/malscan.sarif for full evidence.\n\n",
			pluralise("malware finding", len(res.Findings)))
	}

	if len(res.Warnings) > 0 && verbose {
		b.WriteString(display.Header(t, "Warnings"))
		b.WriteByte('\n')
		for _, w := range res.Warnings {
			fmt.Fprintf(&b, "  • %s\n", w)
		}
		b.WriteByte('\n')
	}

	fmt.Print(b.String())
}

func truncateCmd(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
