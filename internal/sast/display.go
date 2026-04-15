package sast

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/vulnetix/cli/internal/display"
)

// PrintPrettySummary prints a styled SAST findings table to stdout.
// If resultsOnly is true, stays silent when there are no findings.
func PrintPrettySummary(report *SASTReport, resultsOnly bool) {
	if report == nil {
		return
	}
	if resultsOnly && len(report.Findings) == 0 {
		return
	}

	t := display.NewTerminal()
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, display.Header(t, "SAST Analysis"))

	if len(report.Findings) == 0 {
		fmt.Fprintf(os.Stdout, "  %s No findings (%d rules evaluated)\n",
			display.CheckMark(t), report.RulesLoaded)
		return
	}

	// Sort findings: critical > high > medium > low > info, then by artifact URI.
	sorted := make([]Finding, len(report.Findings))
	copy(sorted, report.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		si := severityOrd(sorted[i].Severity)
		sj := severityOrd(sorted[j].Severity)
		if si != sj {
			return si < sj
		}
		return sorted[i].ArtifactURI < sorted[j].ArtifactURI
	})

	sevColor := func(s string) string { return display.SeverityText(t, strings.ToLower(s)) }

	cols := []display.Column{
		{Header: "Rule", MinWidth: 12, MaxWidth: 16},
		{Header: "Severity", MinWidth: 8, MaxWidth: 10, Color: sevColor},
		{Header: "Location", MinWidth: 10, MaxWidth: 40, Color: func(s string) string {
			return display.Teal(t, s)
		}},
		{Header: "Message", MinWidth: 20, MaxWidth: 50},
	}

	rows := make([][]string, 0, len(sorted))
	for _, f := range sorted {
		location := f.ArtifactURI
		if f.StartLine > 0 {
			location = fmt.Sprintf("%s:%d", f.ArtifactURI, f.StartLine)
		}
		label := f.Severity
		if l, ok := SeverityLabel[f.Severity]; ok {
			label = l
		}
		rows = append(rows, []string{f.RuleID, label, location, f.Message})
	}

	fmt.Fprint(os.Stdout, display.Table(t, cols, rows))
	fmt.Fprintln(os.Stdout)

	// Summary counts.
	counts := map[string]int{}
	for _, f := range report.Findings {
		counts[f.Severity]++
	}
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	fmt.Fprintf(os.Stdout, "  %d %s across %d rules: %s\n",
		len(report.Findings), pluralize("finding", len(report.Findings)),
		report.RulesLoaded, strings.Join(parts, ", "))
}

func severityOrd(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "info":
		return 4
	default:
		return 5
	}
}

func pluralize(word string, n int) string {
	if n == 1 {
		return word
	}
	return word + "s"
}
