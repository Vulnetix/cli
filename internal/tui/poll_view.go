package tui

import (
	"fmt"
	"strings"
)

func renderPollPhase(m *Model) string {
	var b strings.Builder

	b.WriteString(styleTitle.Render("Polling for scan results..."))
	b.WriteString("\n\n")

	complete := 0
	errored := 0

	for i, t := range m.tasks {
		name := styleFileName.Render(t.File.RelPath)

		switch t.Status {
		case "polling":
			elapsed := styleElapsed.Render(fmt.Sprintf("(%.1fs)", t.PollDuration().Seconds()))
			scanID := styleScanID.Render(fmt.Sprintf("[%s]", t.ScanID))
			spinner := m.spinners[i%len(m.spinners)].View()
			b.WriteString(fmt.Sprintf("  %s %s  processing... %s %s\n", spinner, name, scanID, elapsed))
		case "complete":
			complete++
			elapsed := styleElapsed.Render(fmt.Sprintf("(%.1fs)", t.TotalDuration().Seconds()))
			vulnCount := len(t.Vulns)
			vulnStr := fmt.Sprintf("%d vulns found", vulnCount)
			if vulnCount == 0 {
				vulnStr = "no vulnerabilities"
			}
			b.WriteString(fmt.Sprintf("  %s %s  %s %s\n", styleCheck.Render(), name, vulnStr, elapsed))
		case "error":
			errored++
			elapsed := styleElapsed.Render(fmt.Sprintf("(%.1fs)", t.TotalDuration().Seconds()))
			errMsg := "scan failed"
			if t.Error != nil {
				errMsg = t.Error.Error()
			}
			b.WriteString(fmt.Sprintf("  %s %s  %s %s\n", styleCross.Render(), name,
				lipglossErrorStyle.Render(errMsg), elapsed))
		case "uploaded":
			// Waiting to start polling
			b.WriteString(fmt.Sprintf("  %s %s  waiting...\n", styleCheck.Render("\u2022"), name))
		default:
			b.WriteString(fmt.Sprintf("  %s %s  %s\n", styleCheck.Render("\u2022"), name, t.Status))
		}
	}

	b.WriteString("\n")
	total := 0
	for _, t := range m.tasks {
		if t.ScanID != "" {
			total++
		}
	}
	status := fmt.Sprintf("  %d/%d complete", complete, total)
	if errored > 0 {
		status += fmt.Sprintf(" | %d errors", errored)
	}
	b.WriteString(styleStatusBar.Render(status))
	b.WriteString("\n")

	return b.String()
}
