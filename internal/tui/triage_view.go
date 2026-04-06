package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/vulnetix/cli/internal/triage"
)

type triageDetailTab int

const (
	triageTabOverview triageDetailTab = iota
	triageTabRemediation
	triageTabFixes
)

func (d triageDetailTab) String() string {
	return []string{"Overview", "Remediation", "Fixes"}[d]
}

// TriageOptions configures the triage TUI.
type TriageOptions struct {
	// GHClient is the GitHub API client used to apply resolutions.
	// May be nil when GitHub integration is unavailable.
	GHClient *triage.GitHubClient
	// Repo is the "owner/repo" string for GitHub API calls.
	Repo string
	// VulnetixDir is the path to the .vulnetix directory for memory persistence.
	// Defaults to ".vulnetix" in the current working directory when empty.
	VulnetixDir string
}

// TriageModel is the bubbletea model for the triage TUI.
type TriageModel struct {
	alerts      []triage.EnrichedAlert
	selectedIdx int
	detailTab   triageDetailTab
	quiting     bool
	width       int
	height      int
	showHelp    bool

	// Resolve modal – non-nil while the overlay is open.
	resolveModal *ResolveModal

	// Options for GitHub/memory integration.
	opts TriageOptions
}

// NewTriageModel creates a new triage TUI model.
func NewTriageModel(alerts []triage.EnrichedAlert, opts TriageOptions) *TriageModel {
	if opts.VulnetixDir == "" {
		opts.VulnetixDir = triage.DefaultVulnetixDir()
	}
	return &TriageModel{
		alerts:    alerts,
		detailTab: triageTabOverview,
		opts:      opts,
	}
}

// Init implements tea.Model.
func (m *TriageModel) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model.
func (m *TriageModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Route messages to the resolve modal first when it is open.
	if m.resolveModal != nil {
		updated, cmd, close := m.resolveModal.Update(msg)
		m.resolveModal = updated
		if close {
			m.resolveModal = nil
			return m, nil
		}

		// When the modal finishes, refresh the alert's displayed state.
		if done, ok := msg.(ResolveCompleteMsg); ok && done.Err == nil {
			m.applyResolvedStatus(done.AlertNumber, done.VEXStatus)
		}

		return m, cmd
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case msg.String() == "q" || msg.String() == "ctrl+c":
			m.quiting = true
			return m, tea.Quit
		case msg.String() == "up" || msg.String() == "k":
			if m.selectedIdx > 0 {
				m.selectedIdx--
			}
		case msg.String() == "down" || msg.String() == "j":
			if m.selectedIdx < len(m.alerts)-1 {
				m.selectedIdx++
			}
		case msg.String() == "tab":
			m.detailTab = triageDetailTab((int(m.detailTab) + 1) % 3)
		case msg.String() == "1":
			m.detailTab = triageTabOverview
		case msg.String() == "2":
			m.detailTab = triageTabRemediation
		case msg.String() == "3":
			m.detailTab = triageTabFixes
		case msg.String() == "?":
			m.showHelp = !m.showHelp
		case msg.String() == "r":
			if len(m.alerts) > 0 && m.selectedIdx >= 0 && m.selectedIdx < len(m.alerts) {
				a := m.alerts[m.selectedIdx].Alert
				m.resolveModal = newResolveModal(a, m.opts.GHClient, m.opts.Repo, m.opts.VulnetixDir)
				return m, m.resolveModal.Init()
			}
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case ResolveCompleteMsg:
		// Received from the modal's async cmd after the modal has already
		// forwarded it; also handle here to update the list in case the modal
		// was closed before the msg arrived (unlikely but defensive).
		if msg.Err == nil {
			m.applyResolvedStatus(msg.AlertNumber, msg.VEXStatus)
		}
	}
	return m, nil
}

// applyResolvedStatus updates the State field of the matching alert in the list
// so the table row reflects the new status immediately.
func (m *TriageModel) applyResolvedStatus(alertNumber, vexStatus string) {
	for i := range m.alerts {
		if m.alerts[i].Alert.Number == alertNumber {
			m.alerts[i].Alert.State = vexStatus
			break
		}
	}
}

// View implements tea.Model.
func (m *TriageModel) View() string {
	if m.quiting {
		return ""
	}

	var b strings.Builder

	// Summary bar
	total := len(m.alerts)
	critical := 0
	fixable := 0
	for _, a := range m.alerts {
		if a.Alert.Severity == "critical" {
			critical++
		}
		if a.Fixes != nil && a.Fixes.HasFix() {
			fixable++
		}
	}

	summary := fmt.Sprintf("  %d alerts | %d critical | %d fixable", total, critical, fixable)
	b.WriteString(styleSummaryBar.Render(summary))
	b.WriteString("\n")

	if total == 0 {
		b.WriteString(styleStatusBar.Render("  No vulnerability alerts."))
		b.WriteString("\n\n")
		b.WriteString(helpTriageShort())
		return b.String()
	}

	// Alert list table header
	b.WriteString(styleDetailHeader.Render(fmt.Sprintf("  %-24s %-10s %-22s %-22s %-22s",
		"CVE / Rule", "Severity", "State / VEX Status", "Package", "Manifest")))
	b.WriteString("\n")

	// Render rows
	visibleRows := m.height - 14
	if visibleRows < 5 {
		visibleRows = 5
	}
	if visibleRows > total {
		visibleRows = total
	}

	for i := 0; i < visibleRows; i++ {
		a := m.alerts[i]
		selected := i == m.selectedIdx

		cve := truncate(a.Alert.Identifier(), 24)
		sev := SeverityStyle(a.Alert.Severity).Render(padRight(strings.ToUpper(a.Alert.Severity), 10))
		state := padRight(a.Alert.State, 22)
		var pkg string
		switch a.Alert.Ecosystem {
		case "codeql":
			pkg = truncate(a.Alert.Manifest, 22)
		case "secrets":
			pkg = truncate(a.Alert.Description, 22)
		default:
			pkg = truncate(fmt.Sprintf("%s@%s", a.Alert.Package, a.Alert.Version), 22)
		}
		manifest := truncate(a.Alert.Manifest, 22)

		line := fmt.Sprintf("  %-24s %-10s %-22s %-22s %-22s",
			cve, sev, state, pkg, manifest)

		if selected {
			line = lipglossSelectedStyle.Render(line)
		}

		b.WriteString(line)
		b.WriteString("\n")
	}

	// Scroll indicator
	if total > visibleRows {
		b.WriteString(styleStatusBar.Render(fmt.Sprintf("  showing %d of %d", visibleRows, total)))
		b.WriteString("\n")
	}

	// Detail panel
	if m.selectedIdx >= 0 && m.selectedIdx < total {
		b.WriteString("\n")
		b.WriteString(m.renderDetail())
	}

	// Help
	b.WriteString("\n")
	if m.showHelp {
		b.WriteString(helpTriage())
	} else {
		b.WriteString(helpTriageShort())
	}

	// Resolve modal overlay
	if m.resolveModal != nil {
		modal := m.resolveModal.View(m.width)
		// Centre the modal horizontally.
		modalWidth := lipgloss.Width(modal)
		leftPad := (m.width - modalWidth) / 2
		if leftPad < 0 {
			leftPad = 0
		}
		pad := strings.Repeat(" ", leftPad)
		lines := strings.Split(modal, "\n")
		var centred []string
		for _, l := range lines {
			centred = append(centred, pad+l)
		}
		// Overlay: append after a separator so bubbletea positions it on screen.
		b.WriteString("\n")
		b.WriteString(strings.Join(centred, "\n"))
	}

	return b.String()
}

func (m *TriageModel) renderDetail() string {
	var b strings.Builder
	a := m.alerts[m.selectedIdx]

	// Tab bar
	tabs := []string{"Overview", "Remediation", "Fixes"}
	var tabBar []string
	for i, name := range tabs {
		label := fmt.Sprintf("[%d] %s", i+1, name)
		if triageDetailTab(i) == m.detailTab {
			tabBar = append(tabBar, styleTabActive.Render(label))
		} else {
			tabBar = append(tabBar, styleTabInactive.Render(label))
		}
	}
	b.WriteString("  " + strings.Join(tabBar, "  "))
	b.WriteString("\n\n")

	switch m.detailTab {
	case triageTabOverview:
		b.WriteString(overviewTab(a))
	case triageTabRemediation:
		b.WriteString(remediationTab(a))
	case triageTabFixes:
		b.WriteString(fixesTab(a))
	}

	return styleDetailContent.Render(b.String())
}

func overviewTab(a triage.EnrichedAlert) string {
	var b strings.Builder

	if a.Error != "" {
		return styleDetailContent.Render("  VDB Error: " + a.Error)
	}

	fmt.Fprintf(&b, "  Alert #   : %s\n", a.Alert.Number)
	fmt.Fprintf(&b, "  State     : %s\n", a.Alert.State)
	if a.Alert.CVE != "" {
		fmt.Fprintf(&b, "  CVE       : %s\n", a.Alert.CVE)
	}
	if a.Alert.RuleID != "" {
		fmt.Fprintf(&b, "  Rule      : %s\n", a.Alert.RuleID)
	}
	if a.Alert.Description != "" {
		fmt.Fprintf(&b, "  Finding   : %s\n", a.Alert.Description)
	}
	if a.Alert.Package != "" {
		fmt.Fprintf(&b, "  Package   : %s@%s\n", a.Alert.Package, a.Alert.Version)
	}
	fmt.Fprintf(&b, "  Ecosystem : %s\n", a.Alert.Ecosystem)
	if a.Alert.Manifest != "" {
		fmt.Fprintf(&b, "  File      : %s\n", a.Alert.Manifest)
	}
	if a.Alert.CWE != "" {
		fmt.Fprintf(&b, "  CWE       : %s\n", a.Alert.CWE)
	}
	fmt.Fprintf(&b, "  URL       : %s\n", a.Alert.URL)

	if a.Fixes != nil && a.Fixes.HasFix() {
		b.WriteString("  Fix status: Fix available\n")
	} else {
		b.WriteString("  Fix status: No fix known\n")
	}

	if a.Remediation != nil {
		b.WriteString("\n  Remediation summary available — press [2] for details\n")
	}

	return styleDetailContent.Render(b.String())
}

func remediationTab(a triage.EnrichedAlert) string {
	if a.Error != "" {
		return styleDetailContent.Render("  VDB Error: " + a.Error)
	}
	if a.Remediation == nil {
		return styleDetailContent.Render("  No remediation data available")
	}
	return styleDetailContent.Render(formatJSONPreview(a.Remediation, 25))
}

func fixesTab(a triage.EnrichedAlert) string {
	var b strings.Builder

	if a.Error != "" {
		return styleDetailContent.Render("  VDB Error: " + a.Error)
	}
	if a.Fixes == nil {
		return styleDetailContent.Render("  No fix data available")
	}

	sections := []struct {
		name string
		data map[string]any
	}{
		{"Registry", a.Fixes.Registry},
		{"Distributions", a.Fixes.Distributions},
		{"Source", a.Fixes.Source},
	}
	for _, sec := range sections {
		fmt.Fprintf(&b, "  [%s]\n", sec.name)
		if sec.data == nil {
			b.WriteString("    No data\n")
			continue
		}
		jsonBytes, _ := json.MarshalIndent(sec.data, "    ", "  ")
		lines := strings.Split(string(jsonBytes), "\n")
		if len(lines) > 10 {
			lines = append(lines[:10], "    ...")
		}
		for _, line := range lines {
			fmt.Fprintf(&b, "    %s\n", line)
		}
	}
	return b.String()
}

func formatJSONPreview(data any, maxLines int) string {
	jsonBytes, err := json.MarshalIndent(data, "  ", "  ")
	if err != nil {
		return "  Error rendering data"
	}
	lines := strings.Split(string(jsonBytes), "\n")
	limit := min(len(lines), maxLines)
	if len(lines) > maxLines {
		lines = append(lines[:limit], "  ...")
	}
	return strings.Join(lines, "\n  ")
}

func helpTriage() string {
	return styleHelp.Render(
		"\n  ↑/↓ navigate  |  Tab cycle detail tabs  |  1-3 select tab  |  r resolve  |  ? hide help  |  q quit\n",
	)
}

func helpTriageShort() string {
	return styleHelp.Render("  ↑/↓ navigate  |  Tab cycle  |  r resolve  |  ? help  |  q quit")
}

// RunTriage starts the triage TUI program.
func RunTriage(alerts []triage.EnrichedAlert, opts TriageOptions) error {
	model := NewTriageModel(alerts, opts)
	p := tea.NewProgram(
		model,
		tea.WithAltScreen(),
		tea.WithOutput(os.Stderr),
	)

	_, err := p.Run()
	if err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}
	return nil
}
