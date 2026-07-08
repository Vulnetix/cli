package tui

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
	// VexFile is the path to the generated VEX document, if any.
	VexFile string
	// Err is non-nil if either operation failed.
	Err error
}
