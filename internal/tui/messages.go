package tui

import "github.com/vulnetix/cli/internal/scan"

// TaskUpdatedMsg is sent when a scan task's status changes.
type TaskUpdatedMsg struct {
	Task *scan.ScanTask
}

// AllUploadsCompleteMsg is sent when all uploads have finished.
type AllUploadsCompleteMsg struct {
	Tasks []*scan.ScanTask
}

// AllPollsCompleteMsg is sent when all polls have finished.
type AllPollsCompleteMsg struct {
	Tasks []*scan.ScanTask
}

// DetailLoadedMsg is sent when lazy-loaded detail data arrives.
type DetailLoadedMsg struct {
	VulnID string
	Tab    DetailTab
	Data   map[string]interface{}
	Err    error
}

// OutputSavedMsg is sent when output has been written to a file.
type OutputSavedMsg struct {
	Path string
	Err  error
}

// ResolveCompleteMsg is sent when a triage resolution attempt finishes.
type ResolveCompleteMsg struct {
	// AlertNumber is the provider alert number that was resolved.
	AlertNumber string
	// VEXStatus is the chosen VEX status (for updating the in-memory list).
	VEXStatus string
	// GitHubUpdated is true when a GitHub PATCH call was made successfully.
	GitHubUpdated bool
	// MemorySaved is true when memory.yaml was updated successfully.
	MemorySaved bool
	// Err is non-nil if either operation failed.
	Err error
}

// DetailTab identifies which detail tab to display.
type DetailTab int

const (
	TabScores DetailTab = iota
	TabExploits
	TabTimeline
	TabFixes
	TabRemediation
)

// TabName returns the display name for a detail tab.
func (t DetailTab) TabName() string {
	switch t {
	case TabScores:
		return "Scores"
	case TabExploits:
		return "Exploits"
	case TabTimeline:
		return "Timeline"
	case TabFixes:
		return "Fixes"
	case TabRemediation:
		return "Remediation"
	default:
		return "Unknown"
	}
}

// NumTabs is the total number of detail tabs.
const NumTabs = 5
