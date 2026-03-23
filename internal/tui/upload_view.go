package tui

import (
	"fmt"
	"strings"
)

func renderUploadPhase(m *Model) string {
	var b strings.Builder

	b.WriteString(styleTitle.Render("Uploading files to VDB API v2..."))
	b.WriteString("\n\n")

	uploaded := 0
	errored := 0

	for i, t := range m.tasks {
		name := styleFileName.Render(t.File.RelPath)
		elapsed := styleElapsed.Render(fmt.Sprintf("(%.1fs)", t.UploadDuration().Seconds()))

		switch t.Status {
		case "queued":
			b.WriteString(fmt.Sprintf("  %s %s  queued\n", styleCheck.Render("\u2022"), name))
		case "uploading":
			spinner := m.spinners[i%len(m.spinners)].View()
			b.WriteString(fmt.Sprintf("  %s %s  uploading... %s\n", spinner, name, elapsed))
		case "uploaded":
			uploaded++
			scanID := ""
			if t.ScanID != "" {
				scanID = styleScanID.Render(fmt.Sprintf("scan-id: %s", t.ScanID))
			}
			b.WriteString(fmt.Sprintf("  %s %s  %s %s\n", styleCheck.Render(), name, scanID, elapsed))
		case "error":
			errored++
			errMsg := "unknown error"
			if t.Error != nil {
				errMsg = t.Error.Error()
			}
			b.WriteString(fmt.Sprintf("  %s %s  %s %s\n", styleCross.Render(), name,
				lipglossErrorStyle.Render(errMsg), elapsed))
		default:
			b.WriteString(fmt.Sprintf("  %s %s  %s\n", styleCheck.Render("\u2022"), name, t.Status))
		}
	}

	b.WriteString("\n")
	total := len(m.tasks)
	status := fmt.Sprintf("  %d/%d uploaded", uploaded, total)
	if errored > 0 {
		status += fmt.Sprintf(" | %d errors", errored)
	}
	b.WriteString(styleStatusBar.Render(status))
	b.WriteString("\n")

	return b.String()
}
