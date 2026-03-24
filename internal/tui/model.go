package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/vulnetix/cli/internal/gitctx"
	"github.com/vulnetix/cli/internal/scan"
	"github.com/vulnetix/cli/internal/vdb"
)

// Phase represents the current phase of the scan TUI.
type Phase int

const (
	PhaseUploading Phase = iota
	PhasePolling
	PhaseResults
)

// Additional lipgloss styles used by views
var (
	lipglossErrorStyle    = lipgloss.NewStyle().Foreground(colorError)
	lipglossSelectedStyle = lipgloss.NewStyle().Bold(true).Background(lipgloss.Color("#333333"))
)

// Model is the main bubbletea model for the scan TUI.
type Model struct {
	// State
	phase   Phase
	quiting bool

	// Data
	client  *vdb.Client
	tasks   []*scan.ScanTask
	ctx     context.Context
	cancel  context.CancelFunc

	// Upload/poll engines
	uploadEngine *scan.UploadEngine
	pollEngine   *scan.PollEngine
	msgCh        chan tea.Msg

	// UI components
	spinners []spinner.Model

	// Results
	allVulns     []scan.VulnSummary
	selectedIdx  int
	scrollOffset int
	detailTab    DetailTab
	loadingDetail bool

	// Output menu
	outputMenu    bool
	outputFormat  string
	outputPath    string
	outputMenuIdx int

	// Terminal dimensions
	width  int
	height int

	// Help toggle
	showHelp bool

	// Mutex for concurrent task updates
	mu sync.Mutex
}

// NewModel creates a new TUI model.
func NewModel(client *vdb.Client, files []scan.DetectedFile, pollInterval int, outputFormat string, gitCtx *gitctx.GitContext, repoRoot string) *Model {
	ctx, cancel := context.WithCancel(context.Background())

	// Create spinners for each task
	spinners := make([]spinner.Model, len(files))
	for i := range spinners {
		s := spinner.New()
		s.Spinner = spinner.Dot
		s.Style = lipgloss.NewStyle().Foreground(colorAccent)
		spinners[i] = s
	}

	// Create tasks
	tasks := make([]*scan.ScanTask, len(files))
	for i, f := range files {
		tasks[i] = &scan.ScanTask{
			File:   f,
			Status: "queued",
		}
	}

	m := &Model{
		phase:        PhaseUploading,
		client:       client,
		tasks:        tasks,
		ctx:          ctx,
		cancel:       cancel,
		spinners:     spinners,
		selectedIdx:  0,
		detailTab:    TabScores,
		outputFormat: outputFormat,
		outputPath:   fmt.Sprintf("./vulnetix-scan-%s.json", time.Now().Format("20060102-150405")),
		msgCh:        make(chan tea.Msg, 100),
	}

	m.uploadEngine = &scan.UploadEngine{
		Client:      client,
		Concurrency: 5,
		GitContext:  gitCtx,
		RepoRoot:    repoRoot,
		OnProgress: func(t *scan.ScanTask) {
			m.msgCh <- TaskUpdatedMsg{Task: t}
		},
	}

	m.pollEngine = &scan.PollEngine{
		Client:   client,
		Interval: time.Duration(pollInterval) * time.Second,
		OnProgress: func(t *scan.ScanTask) {
			m.msgCh <- TaskUpdatedMsg{Task: t}
		},
	}

	return m
}

// Init starts the TUI. Implements tea.Model.
func (m *Model) Init() tea.Cmd {
	cmds := make([]tea.Cmd, 0, len(m.spinners)+2)

	// Start all spinners
	for i := range m.spinners {
		cmds = append(cmds, m.spinners[i].Tick)
	}

	// Start listening for async messages
	cmds = append(cmds, m.listenForMessages())

	// Kick off uploads
	cmds = append(cmds, m.startUploads())

	return tea.Batch(cmds...)
}

// Update handles messages. Implements tea.Model.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		cmd := m.handleKey(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
		if m.quiting {
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case spinner.TickMsg:
		for i := range m.spinners {
			var cmd tea.Cmd
			m.spinners[i], cmd = m.spinners[i].Update(msg)
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
		}

	case TaskUpdatedMsg:
		// Find and update the matching task
		m.mu.Lock()
		for i, t := range m.tasks {
			if t.File.Path == msg.Task.File.Path {
				m.tasks[i] = msg.Task
				break
			}
		}
		m.mu.Unlock()
		cmds = append(cmds, m.listenForMessages())

	case AllUploadsCompleteMsg:
		m.tasks = msg.Tasks
		m.phase = PhasePolling
		cmds = append(cmds, m.startPolling())
		cmds = append(cmds, m.listenForMessages())

	case AllPollsCompleteMsg:
		m.tasks = msg.Tasks
		m.phase = PhaseResults
		m.allVulns = scan.AllVulns(m.tasks)

	case DetailLoadedMsg:
		m.loadingDetail = false
		if msg.Err != nil {
			// Store error as a note in the data
			errData := map[string]interface{}{"error": msg.Err.Error()}
			m.applyDetailData(msg.VulnID, msg.Tab, errData)
		} else {
			m.applyDetailData(msg.VulnID, msg.Tab, msg.Data)
		}

	case OutputSavedMsg:
		if msg.Err != nil {
			// Could show error but for now just close menu
		}
		m.outputMenu = false
	}

	return m, tea.Batch(cmds...)
}

// View renders the TUI. Implements tea.Model.
func (m *Model) View() string {
	if m.quiting {
		return ""
	}

	var content string

	switch m.phase {
	case PhaseUploading:
		content = renderUploadPhase(m)
	case PhasePolling:
		content = renderPollPhase(m)
	case PhaseResults:
		if m.outputMenu {
			content = renderOutputMenu(m)
		} else {
			content = renderResultsPhase(m)
		}
	}

	return content
}

// handleKey processes keyboard input.
func (m *Model) handleKey(msg tea.KeyMsg) tea.Cmd {
	// Output menu has its own key handling
	if m.outputMenu {
		return m.handleOutputMenuKey(msg)
	}

	switch {
	case key.Matches(msg, keys.Quit):
		m.quiting = true
		m.cancel()
		return tea.Quit

	case key.Matches(msg, keys.Up):
		if m.phase == PhaseResults && m.selectedIdx > 0 {
			m.selectedIdx--
			if m.selectedIdx < m.scrollOffset {
				m.scrollOffset = m.selectedIdx
			}
		}

	case key.Matches(msg, keys.Down):
		if m.phase == PhaseResults && m.selectedIdx < len(m.allVulns)-1 {
			m.selectedIdx++
			visibleRows := m.height - 12
			if visibleRows < 5 {
				visibleRows = 5
			}
			if m.selectedIdx >= m.scrollOffset+visibleRows {
				m.scrollOffset = m.selectedIdx - visibleRows + 1
			}
		}

	case key.Matches(msg, keys.PageUp):
		if m.phase == PhaseResults {
			m.selectedIdx -= 10
			if m.selectedIdx < 0 {
				m.selectedIdx = 0
			}
			m.scrollOffset = m.selectedIdx
		}

	case key.Matches(msg, keys.PageDown):
		if m.phase == PhaseResults {
			m.selectedIdx += 10
			if m.selectedIdx >= len(m.allVulns) {
				m.selectedIdx = len(m.allVulns) - 1
			}
			if m.selectedIdx < 0 {
				m.selectedIdx = 0
			}
			visibleRows := m.height - 12
			if visibleRows < 5 {
				visibleRows = 5
			}
			if m.selectedIdx >= m.scrollOffset+visibleRows {
				m.scrollOffset = m.selectedIdx - visibleRows + 1
			}
		}

	case key.Matches(msg, keys.Enter):
		if m.phase == PhaseResults {
			return m.loadDetailForSelected()
		}

	case key.Matches(msg, keys.Tab):
		if m.phase == PhaseResults {
			m.detailTab = DetailTab((int(m.detailTab) + 1) % NumTabs)
			return m.loadDetailForSelected()
		}

	case key.Matches(msg, keys.TabScores):
		if m.phase == PhaseResults {
			m.detailTab = TabScores
		}

	case key.Matches(msg, keys.TabExploit):
		if m.phase == PhaseResults {
			m.detailTab = TabExploits
			return m.loadDetailForSelected()
		}

	case key.Matches(msg, keys.TabTime):
		if m.phase == PhaseResults {
			m.detailTab = TabTimeline
			return m.loadDetailForSelected()
		}

	case key.Matches(msg, keys.TabFixes):
		if m.phase == PhaseResults {
			m.detailTab = TabFixes
			return m.loadDetailForSelected()
		}

	case key.Matches(msg, keys.TabRemed):
		if m.phase == PhaseResults {
			m.detailTab = TabRemediation
			return m.loadDetailForSelected()
		}

	case key.Matches(msg, keys.Output):
		if m.phase == PhaseResults {
			m.outputMenu = true
			m.outputMenuIdx = 0
		}

	case key.Matches(msg, keys.Help):
		m.showHelp = !m.showHelp
	}

	return nil
}

func (m *Model) handleOutputMenuKey(msg tea.KeyMsg) tea.Cmd {
	switch {
	case key.Matches(msg, keys.Escape):
		m.outputMenu = false

	case key.Matches(msg, keys.Up):
		if m.outputMenuIdx > 0 {
			m.outputMenuIdx--
		}

	case key.Matches(msg, keys.Down):
		if m.outputMenuIdx < 2 {
			m.outputMenuIdx++
		}

	case key.Matches(msg, keys.Enter):
		formats := []string{"cdx17", "cdx16", "json"}
		m.outputFormat = formats[m.outputMenuIdx]
		return m.doSaveOutput()

	case key.Matches(msg, keys.Quit):
		m.outputMenu = false
	}
	return nil
}

// Async operations

func (m *Model) listenForMessages() tea.Cmd {
	return func() tea.Msg {
		return <-m.msgCh
	}
}

func (m *Model) startUploads() tea.Cmd {
	return func() tea.Msg {
		// Extract files from tasks
		files := make([]scan.DetectedFile, len(m.tasks))
		for i, t := range m.tasks {
			files[i] = t.File
		}
		tasks := m.uploadEngine.UploadAll(m.ctx, files)
		return AllUploadsCompleteMsg{Tasks: tasks}
	}
}

func (m *Model) startPolling() tea.Cmd {
	return func() tea.Msg {
		m.pollEngine.PollAll(m.ctx, m.tasks)
		return AllPollsCompleteMsg{Tasks: m.tasks}
	}
}

func (m *Model) loadDetailForSelected() tea.Cmd {
	if m.selectedIdx < 0 || m.selectedIdx >= len(m.allVulns) {
		return nil
	}

	v := &m.allVulns[m.selectedIdx]
	tab := m.detailTab

	// Scores tab doesn't need lazy loading
	if tab == TabScores {
		return nil
	}

	// Check if data is already loaded
	switch tab {
	case TabExploits:
		if v.Exploits != nil {
			return nil
		}
	case TabTimeline:
		if v.Timeline != nil {
			return nil
		}
	case TabFixes:
		if v.Fixes != nil {
			return nil
		}
	case TabRemediation:
		if v.Remediation != nil {
			return nil
		}
	}

	m.loadingDetail = true
	vulnID := v.VulnID

	return func() tea.Msg {
		data, err := m.fetchDetail(vulnID, tab)
		return DetailLoadedMsg{
			VulnID: vulnID,
			Tab:    tab,
			Data:   data,
			Err:    err,
		}
	}
}

func (m *Model) fetchDetail(vulnID string, tab DetailTab) (map[string]interface{}, error) {
	switch tab {
	case TabExploits:
		return m.client.GetExploits(vulnID)
	case TabTimeline:
		return m.client.V2Timeline(vulnID, vdb.V2TimelineParams{})
	case TabFixes:
		// Fetch all three fix endpoints in parallel (like v2FixesMerged)
		return m.fetchFixesMerged(vulnID)
	case TabRemediation:
		return m.client.V2RemediationPlan(vulnID, vdb.V2RemediationParams{
			IncludeGuidance:          true,
			IncludeVerificationSteps: true,
		})
	}
	return nil, fmt.Errorf("unknown tab: %d", tab)
}

func (m *Model) fetchFixesMerged(vulnID string) (map[string]interface{}, error) {
	type result struct {
		key  string
		data map[string]interface{}
		err  error
	}

	ch := make(chan result, 3)
	var wg sync.WaitGroup
	p := vdb.V2QueryParams{}

	wg.Add(3)
	go func() {
		defer wg.Done()
		data, err := m.client.V2RegistryFixes(vulnID, p)
		ch <- result{"registry", data, err}
	}()
	go func() {
		defer wg.Done()
		data, err := m.client.V2DistributionPatches(vulnID, p)
		ch <- result{"distributions", data, err}
	}()
	go func() {
		defer wg.Done()
		data, err := m.client.V2SourceFixes(vulnID, p)
		ch <- result{"source", data, err}
	}()
	go func() {
		wg.Wait()
		close(ch)
	}()

	merged := map[string]interface{}{
		"identifier": vulnID,
	}
	for r := range ch {
		if r.err != nil {
			merged[r.key] = map[string]interface{}{"error": r.err.Error()}
		} else {
			merged[r.key] = r.data
		}
	}
	return merged, nil
}

func (m *Model) applyDetailData(vulnID string, tab DetailTab, data map[string]interface{}) {
	for i := range m.allVulns {
		if m.allVulns[i].VulnID == vulnID {
			switch tab {
			case TabExploits:
				m.allVulns[i].Exploits = &data
			case TabTimeline:
				m.allVulns[i].Timeline = &data
			case TabFixes:
				m.allVulns[i].Fixes = &scan.FixesMerged{
					Registry:      extractSubMap(data, "registry"),
					Distributions: extractSubMap(data, "distributions"),
					Source:        extractSubMap(data, "source"),
				}
			case TabRemediation:
				m.allVulns[i].Remediation = &data
			}
			break
		}
	}
}

func extractSubMap(data map[string]interface{}, key string) map[string]interface{} {
	if v, ok := data[key].(map[string]interface{}); ok {
		return v
	}
	return nil
}

func (m *Model) doSaveOutput() tea.Cmd {
	return func() tea.Msg {
		err := saveOutput(m.tasks, m.outputFormat, m.outputPath)
		return OutputSavedMsg{Path: m.outputPath, Err: err}
	}
}

// jsonEncoder creates a JSON encoder with standard settings.
func jsonEncoder(w io.Writer) *json.Encoder {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc
}

// Run starts the TUI program. This is the main entry point called from cmd/scan.go.
func Run(client *vdb.Client, files []scan.DetectedFile, pollInterval int, outputFormat string, gitCtx *gitctx.GitContext, repoRoot string) error {
	model := NewModel(client, files, pollInterval, outputFormat, gitCtx, repoRoot)
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
