package tui

// resolve_view.go – the resolve modal that overlays the triage TUI when the
// user presses "r". It steps through:
//   1. Status selection  (↑/↓ + Enter)
//   2. Rationale entry   (freeform text, Enter to submit)
//   3. Submitting        (async, spinner)
//   4. Done / Error      (Esc to dismiss)

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/vulnetix/cli/internal/triage"
)

// resolveModalState is the step the modal is currently on.
type resolveModalState int

const (
	resolveStateSelect     resolveModalState = iota // choosing a status option
	resolveStateRationale                           // typing rationale
	resolveStateSubmitting                          // async in-flight
	resolveStateDone                                // success or error
)

// ResolveModal is the full-screen modal overlay for resolving an alert.
type ResolveModal struct {
	alert       triage.Alert
	options     []triage.ResolutionOption
	selIdx      int
	state       resolveModalState
	rationale   textinput.Model
	chosenOpt   triage.ResolutionOption
	spinner     spinner.Model
	resultMsg   string
	resultErr   bool
	ghClient    *triage.GitHubClient
	repo        string
	vulnetixDir string
	vexFormat   string
}

// newResolveModal creates a fresh modal for the given alert.
func newResolveModal(a triage.Alert, ghClient *triage.GitHubClient, repo, vulnetixDir, vexFormat string) *ResolveModal {
	ti := textinput.New()
	ti.Placeholder = "Type rationale… (required, Enter to submit)"
	ti.CharLimit = 500
	ti.Width = 64

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(ColorAccent)

	return &ResolveModal{
		alert:       a,
		options:     triage.OptionsForAlert(a),
		state:       resolveStateSelect,
		rationale:   ti,
		spinner:     sp,
		ghClient:    ghClient,
		repo:        repo,
		vulnetixDir: vulnetixDir,
		vexFormat:   vexFormat,
	}
}

// Init returns the spinner tick so the spinner animates during submission.
func (m *ResolveModal) Init() tea.Cmd {
	return m.spinner.Tick
}

// Update handles key/message events for the modal.
// Returns (updatedModal, cmd, closeModal).
func (m *ResolveModal) Update(msg tea.Msg) (*ResolveModal, tea.Cmd, bool) {
	switch m.state {
	case resolveStateSelect:
		return m.updateSelect(msg)
	case resolveStateRationale:
		return m.updateRationale(msg)
	case resolveStateSubmitting:
		return m.updateSubmitting(msg)
	case resolveStateDone:
		return m.updateDone(msg)
	}
	return m, nil, false
}

func (m *ResolveModal) updateSelect(msg tea.Msg) (*ResolveModal, tea.Cmd, bool) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc", "q":
			return m, nil, true // close without action
		case "up", "k":
			if m.selIdx > 0 {
				m.selIdx--
			}
		case "down", "j":
			if m.selIdx < len(m.options)-1 {
				m.selIdx++
			}
		case "enter":
			m.chosenOpt = m.options[m.selIdx]
			m.state = resolveStateRationale
			m.rationale.Focus()
			return m, textinput.Blink, false
		}
	}
	return m, nil, false
}

func (m *ResolveModal) updateRationale(msg tea.Msg) (*ResolveModal, tea.Cmd, bool) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			// Step back to status selection.
			m.state = resolveStateSelect
			m.rationale.Blur()
			return m, nil, false
		case "enter":
			// Validate that the user actually typed something.
			text := strings.TrimSpace(m.rationale.Value())
			if text == "" {
				// Flash a hint – stay on rationale screen (error shown in view).
				return m, nil, false
			}
			// Advance to submitting.
			m.state = resolveStateSubmitting
			m.rationale.Blur()
			return m, tea.Batch(m.spinner.Tick, m.doSubmit(text)), false
		}
	}
	// Forward all other events to the text input.
	var cmd tea.Cmd
	m.rationale, cmd = m.rationale.Update(msg)
	return m, cmd, false
}

func (m *ResolveModal) updateSubmitting(msg tea.Msg) (*ResolveModal, tea.Cmd, bool) {
	switch msg := msg.(type) {
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd, false
	case ResolveCompleteMsg:
		if msg.Err != nil {
			m.resultMsg = fmt.Sprintf("Error: %s", msg.Err.Error())
			m.resultErr = true
		} else {
			parts := []string{"Saved to memory"}
			if msg.GitHubUpdated {
				parts = append([]string{"GitHub updated"}, parts...)
			}
			if msg.VexFile != "" {
				parts = append(parts, "VEX written")
			}
			m.resultMsg = strings.Join(parts, " · ")
		}
		m.state = resolveStateDone
		return m, nil, false
	}
	return m, nil, false
}

func (m *ResolveModal) updateDone(msg tea.Msg) (*ResolveModal, tea.Cmd, bool) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc", "enter", "q":
			return m, nil, true // close modal
		}
	}
	return m, nil, false
}

// doSubmit returns a tea.Cmd that performs the async GitHub API call + memory save.
func (m *ResolveModal) doSubmit(rationale string) tea.Cmd {
	alert := m.alert
	opt := m.chosenOpt
	ghClient := m.ghClient
	repo := m.repo
	vulnetixDir := m.vulnetixDir

	vexFormat := m.vexFormat

	return func() tea.Msg {
		var ghErr, memErr, vexErr error
		ghUpdated := false
		var vexFile string

		// 1. GitHub API call (skipped for VEX-only options or missing client).
		if opt.GitHubState != "" && ghClient != nil && repo != "" {
			ghErr = triage.ApplyResolution(context.Background(), ghClient, repo, alert, opt, rationale)
			if ghErr == nil {
				ghUpdated = true
			}
		}

		// 2. Persist to memory.yaml.
		if vulnetixDir != "" {
			memErr = triage.RecordResolutionInMemory(vulnetixDir, alert, opt, rationale)
		}

		// 3. Generate and save VEX document to memory directory.
		if vulnetixDir != "" {
			vexFile, vexErr = triage.WriteVEXForResolution(vulnetixDir, alert, opt, rationale, vexFormat)
		}

		// Report the combined outcome.
		combinedErr := ghErr
		if combinedErr == nil {
			combinedErr = memErr
		} else if memErr != nil {
			combinedErr = fmt.Errorf("github: %w; memory: %s", ghErr, memErr.Error())
		}
		if combinedErr == nil {
			combinedErr = vexErr
		} else if vexErr != nil {
			combinedErr = fmt.Errorf("%w; vex: %s", combinedErr, vexErr.Error())
		}

		return ResolveCompleteMsg{
			AlertNumber:   alert.Number,
			VEXStatus:     opt.VEXStatus,
			GitHubUpdated: ghUpdated,
			MemorySaved:   memErr == nil && vulnetixDir != "",
			VexFile:       vexFile,
			Err:           combinedErr,
		}
	}
}

// View renders the resolve screen as a full-screen view.
func (m *ResolveModal) View(width, height int) string {
	inner := m.renderInner(width)

	style := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorAccent).
		Padding(1, 3).
		Width(width - 4).
		Height(height - 4)

	return style.Render(inner)
}

func (m *ResolveModal) renderInner(width int) string {
	var b strings.Builder

	// Header
	title := lipgloss.NewStyle().Bold(true).Foreground(ColorAccent).Render("  Resolve Alert")
	b.WriteString(title + "\n")

	alertID := m.alert.Identifier()
	eco := m.alert.Ecosystem
	subtitle := lipgloss.NewStyle().Foreground(ColorMuted).
		Render(fmt.Sprintf("  %s  ·  %s  ·  #%s", alertID, eco, m.alert.Number))
	b.WriteString(subtitle + "\n\n")

	switch m.state {
	case resolveStateSelect:
		b.WriteString(m.viewSelect())
	case resolveStateRationale:
		b.WriteString(m.viewRationale())
	case resolveStateSubmitting:
		b.WriteString(m.viewSubmitting())
	case resolveStateDone:
		b.WriteString(m.viewDone())
	}

	return b.String()
}

func (m *ResolveModal) viewSelect() string {
	var b strings.Builder
	b.WriteString(lipgloss.NewStyle().Bold(true).Render("  Select resolution:") + "\n\n")

	for i, opt := range m.options {
		// VEX badge
		vexBadge := lipgloss.NewStyle().Foreground(ColorTeal).Render("→ VEX: " + opt.VEXBadge())

		// Source tag
		var srcTag string
		if opt.GitHubState != "" {
			srcTag = lipgloss.NewStyle().Foreground(ColorAccent).Render("[GH+VEX]")
		} else {
			srcTag = lipgloss.NewStyle().Foreground(ColorMuted).Render("[VEX]   ")
		}

		line := fmt.Sprintf("  %s  %-38s  %s", srcTag, opt.Label, vexBadge)

		if i == m.selIdx {
			line = lipglossSelectedStyle.Render(line)
			// Show description beneath selected row
			desc := lipgloss.NewStyle().Foreground(ColorMuted).Italic(true).
				Render("       " + opt.Description)
			b.WriteString(line + "\n" + desc + "\n")
		} else {
			b.WriteString(line + "\n")
		}
	}

	b.WriteString("\n")
	b.WriteString(styleHelp.Render("  ↑/↓  navigate  |  Enter  select  |  Esc  cancel"))
	return b.String()
}

func (m *ResolveModal) viewRationale() string {
	var b strings.Builder

	chosen := lipgloss.NewStyle().Bold(true).Render("  Action: ") +
		lipgloss.NewStyle().Foreground(ColorAccent).Render(m.chosenOpt.Label) +
		"  " +
		lipgloss.NewStyle().Foreground(ColorTeal).Render("→ VEX: "+m.chosenOpt.VEXBadge())

	if m.chosenOpt.GitHubState != "" {
		chosen += "\n" + lipgloss.NewStyle().Foreground(ColorMuted).
			Render(fmt.Sprintf("  GitHub: PATCH state=%q reason=%q", m.chosenOpt.GitHubState, m.chosenOpt.GitHubReason))
	}

	b.WriteString(chosen + "\n\n")

	b.WriteString(lipgloss.NewStyle().Bold(true).Render("  Rationale") +
		lipgloss.NewStyle().Foreground(colorError).Render(" *") +
		lipgloss.NewStyle().Foreground(ColorMuted).Render(" (required — used as GitHub comment & VEX justification)") +
		"\n\n")

	b.WriteString("  " + m.rationale.View() + "\n\n")

	// Validation hint when empty
	if strings.TrimSpace(m.rationale.Value()) == "" {
		b.WriteString(lipgloss.NewStyle().Foreground(colorError).
			Render("  Please enter a rationale before submitting.") + "\n\n")
	}

	b.WriteString(styleHelp.Render("  Enter  submit  |  Esc  back"))
	return b.String()
}

func (m *ResolveModal) viewSubmitting() string {
	return fmt.Sprintf("\n  %s  Submitting resolution…\n", m.spinner.View())
}

func (m *ResolveModal) viewDone() string {
	var b strings.Builder
	b.WriteString("\n")
	if m.resultErr {
		icon := lipgloss.NewStyle().Foreground(colorError).Render("✘")
		b.WriteString(fmt.Sprintf("  %s  %s\n\n", icon, m.resultMsg))
	} else {
		icon := lipgloss.NewStyle().Foreground(ColorSuccess).Render("✔")
		b.WriteString(fmt.Sprintf("  %s  %s\n\n", icon, m.resultMsg))

		// Summary
		b.WriteString(lipgloss.NewStyle().Foreground(ColorMuted).
			Render(fmt.Sprintf("  Status   : %s\n", m.chosenOpt.VEXStatus)))
		if m.chosenOpt.VEXJustification != "" {
			b.WriteString(lipgloss.NewStyle().Foreground(ColorMuted).
				Render(fmt.Sprintf("  Justn    : %s\n", m.chosenOpt.VEXJustification)))
		}
		b.WriteString(lipgloss.NewStyle().Foreground(ColorMuted).
			Render(fmt.Sprintf("  Rationale: %s\n", truncate(strings.TrimSpace(m.rationale.Value()), 60))))
	}
	b.WriteString("\n")
	b.WriteString(styleHelp.Render("  Esc / Enter  close"))
	return b.String()
}
