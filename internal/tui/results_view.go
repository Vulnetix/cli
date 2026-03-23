package tui

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vulnetix/cli/internal/scan"
)

func renderResultsPhase(m *Model) string {
	var b strings.Builder

	// Summary bar
	summary := scan.Summarize(m.tasks)
	b.WriteString(styleSummaryBar.Render(summary.FormatSummary()))
	b.WriteString("\n")

	if len(m.allVulns) == 0 {
		b.WriteString(styleStatusBar.Render("  No vulnerabilities found."))
		b.WriteString("\n\n")
		b.WriteString(helpView())
		return b.String()
	}

	// Table header
	header := fmt.Sprintf("  %-18s %-10s %-7s %-7s %-30s %s",
		"Vuln ID", "Severity", "EPSS", "Malware", "Package", "Source")
	b.WriteString(styleDetailHeader.Render(header))
	b.WriteString("\n")

	// Table rows
	visibleRows := m.height - 12 // leave room for header, summary, detail, help
	if visibleRows < 5 {
		visibleRows = 5
	}

	startIdx := m.scrollOffset
	if startIdx > len(m.allVulns)-visibleRows {
		startIdx = len(m.allVulns) - visibleRows
	}
	if startIdx < 0 {
		startIdx = 0
	}

	endIdx := startIdx + visibleRows
	if endIdx > len(m.allVulns) {
		endIdx = len(m.allVulns)
	}

	for i := startIdx; i < endIdx; i++ {
		v := m.allVulns[i]
		selected := i == m.selectedIdx

		// Format fields
		vulnID := truncate(v.VulnID, 18)
		severity := SeverityStyle(v.Severity).Render(padRight(v.Severity, 10))
		epss := "  -  "
		for _, s := range v.Scores {
			if s.Type == "epss" {
				epss = fmt.Sprintf("%.3f", s.Score)
				break
			}
		}
		malware := "  -  "
		if v.IsMalicious {
			malware = styleMalware.Render("  YES")
		}
		pkg := truncate(v.PackageName, 30)
		src := truncate(v.SourceFile, 30)

		line := fmt.Sprintf("  %-18s %s %-7s %-7s %-30s %s",
			vulnID, severity, epss, malware, pkg, src)

		if selected {
			line = lipglossSelectedStyle.Render(line)
		}

		b.WriteString(line)
		b.WriteString("\n")
	}

	// Scroll indicator
	if len(m.allVulns) > visibleRows {
		b.WriteString(styleStatusBar.Render(
			fmt.Sprintf("  showing %d-%d of %d", startIdx+1, endIdx, len(m.allVulns))))
		b.WriteString("\n")
	}

	// Detail panel (if a vuln is selected)
	if m.selectedIdx >= 0 && m.selectedIdx < len(m.allVulns) {
		b.WriteString("\n")
		b.WriteString(renderDetailPanel(m))
	}

	b.WriteString("\n")
	b.WriteString(helpView())

	return b.String()
}

func renderDetailPanel(m *Model) string {
	var b strings.Builder

	v := &m.allVulns[m.selectedIdx]

	// Tab bar
	tabs := []string{"Scores", "Exploits", "Timeline", "Fixes", "Remediation"}
	var tabBar []string
	for i, name := range tabs {
		label := fmt.Sprintf("[%d] %s", i+1, name)
		if DetailTab(i) == m.detailTab {
			tabBar = append(tabBar, styleTabActive.Render(label))
		} else {
			tabBar = append(tabBar, styleTabInactive.Render(label))
		}
	}
	b.WriteString("  " + strings.Join(tabBar, "  "))
	b.WriteString("\n\n")

	// Tab content
	switch m.detailTab {
	case TabScores:
		b.WriteString(renderScoresTab(v))
	case TabExploits:
		b.WriteString(renderLazyTab(v.Exploits, m.loadingDetail, "exploits"))
	case TabTimeline:
		b.WriteString(renderLazyTab(v.Timeline, m.loadingDetail, "timeline"))
	case TabFixes:
		if v.Fixes != nil {
			b.WriteString(renderFixesTab(v.Fixes))
		} else {
			b.WriteString(renderLazyTab(nil, m.loadingDetail, "fixes"))
		}
	case TabRemediation:
		b.WriteString(renderLazyTab(v.Remediation, m.loadingDetail, "remediation"))
	}

	return b.String()
}

func renderScoresTab(v *scan.VulnSummary) string {
	var b strings.Builder
	if len(v.Scores) == 0 {
		b.WriteString(styleDetailContent.Render("  No scores available"))
		return b.String()
	}
	for _, s := range v.Scores {
		label := padRight(strings.ToUpper(s.Type), 16)
		scoreStr := fmt.Sprintf("%.4f", s.Score)
		source := ""
		if s.Source != "" {
			source = fmt.Sprintf("  (%s)", s.Source)
		}
		b.WriteString(styleDetailContent.Render(
			fmt.Sprintf("  %s %s%s", label, scoreStr, source)))
		b.WriteString("\n")
	}
	return b.String()
}

func renderLazyTab(data *map[string]interface{}, loading bool, name string) string {
	if data == nil {
		if loading {
			return styleDetailContent.Render(fmt.Sprintf("  Loading %s...", name))
		}
		return styleDetailContent.Render(fmt.Sprintf("  Press enter to load %s", name))
	}
	// Pretty-print JSON
	jsonBytes, err := json.MarshalIndent(*data, "  ", "  ")
	if err != nil {
		return styleDetailContent.Render("  Error rendering data")
	}
	content := string(jsonBytes)
	// Truncate for display
	lines := strings.Split(content, "\n")
	if len(lines) > 20 {
		lines = append(lines[:20], "  ...")
	}
	return styleDetailContent.Render("  " + strings.Join(lines, "\n  "))
}

func renderFixesTab(fixes *scan.FixesMerged) string {
	var b strings.Builder
	sections := []struct {
		name string
		data map[string]interface{}
	}{
		{"Registry", fixes.Registry},
		{"Distributions", fixes.Distributions},
		{"Source", fixes.Source},
	}
	for _, sec := range sections {
		b.WriteString(styleDetailContent.Render(fmt.Sprintf("  [%s]", sec.name)))
		b.WriteString("\n")
		if sec.data == nil {
			b.WriteString(styleDetailContent.Render("    No data"))
			b.WriteString("\n")
			continue
		}
		jsonBytes, _ := json.MarshalIndent(sec.data, "    ", "  ")
		lines := strings.Split(string(jsonBytes), "\n")
		if len(lines) > 10 {
			lines = append(lines[:10], "    ...")
		}
		for _, line := range lines {
			b.WriteString("    " + line + "\n")
		}
	}
	return b.String()
}

func renderOutputMenu(m *Model) string {
	var b strings.Builder

	b.WriteString(styleOutputMenu.Render(
		styleTitle.Render("Output Options") + "\n\n" +
			"  Format:\n" +
			formatOption("cdx17", "CycloneDX 1.7 (default)", m.outputFormat) +
			formatOption("cdx16", "CycloneDX 1.6", m.outputFormat) +
			formatOption("json", "Raw API JSON", m.outputFormat) +
			"\n  Path: " + m.outputPath + "\n\n" +
			"  Press enter to save, esc to cancel",
	))

	return b.String()
}

func formatOption(key, label, current string) string {
	marker := "  "
	if key == current {
		marker = "> "
	}
	return fmt.Sprintf("    %s[%s] %s\n", marker, key, label)
}

// Helper functions

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

func padRight(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}
