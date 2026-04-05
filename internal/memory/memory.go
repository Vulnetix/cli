// Package memory manages the .vulnetix/memory.yaml file that persists scan state
// between runs — last scan summary, history, and cached findings.
package memory

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// FileName is the basename of the memory file inside .vulnetix/.
	FileName = "memory.yaml"
	// maxHistory is the maximum number of historical scan records to retain.
	maxHistory = 20
)

// ScopeStats records package and vulnerability counts for a single scope bucket.
type ScopeStats struct {
	Packages int `yaml:"packages"`
	Vulns    int `yaml:"vulns"`
}

// ScanRecord summarises one scan run.
type ScanRecord struct {
	Timestamp      string                `yaml:"timestamp"`
	Path           string                `yaml:"path,omitempty"`
	GitBranch      string                `yaml:"git_branch,omitempty"`
	GitCommit      string                `yaml:"git_commit,omitempty"`
	GitRemote      string                `yaml:"git_remote,omitempty"`
	FilesScanned   int                   `yaml:"files_scanned"`
	Packages       int                   `yaml:"packages"`
	Vulns          int                   `yaml:"vulns"`
	Critical       int                   `yaml:"critical"`
	High           int                   `yaml:"high"`
	Medium         int                   `yaml:"medium"`
	Low            int                   `yaml:"low"`
	SBOMPath       string                `yaml:"sbom_path,omitempty"`
	ScopeBreakdown map[string]ScopeStats `yaml:"scope_breakdown,omitempty"`
	IDSRulesPath   string                `yaml:"ids_rules_path,omitempty"`
	IDSRulesCount  int                   `yaml:"ids_rules_count,omitempty"`
}

// Memory is the top-level .vulnetix/memory.yaml structure.
type Memory struct {
	Version  string       `yaml:"version"`
	LastScan *ScanRecord  `yaml:"last_scan,omitempty"`
	History  []ScanRecord `yaml:"history,omitempty"`
}

// Load reads memory.yaml from the given .vulnetix directory.
// If the file does not exist, a fresh Memory is returned without error.
// If the file is corrupt, a fresh Memory is returned (non-fatal).
func Load(vulnetixDir string) (*Memory, error) {
	path := filepath.Join(vulnetixDir, FileName)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Memory{Version: "1"}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	var m Memory
	if err := yaml.Unmarshal(data, &m); err != nil {
		// Silently recover from corrupt files; a fresh scan will overwrite.
		return &Memory{Version: "1"}, nil
	}
	if m.Version == "" {
		m.Version = "1"
	}
	return &m, nil
}

// Save writes m to memory.yaml inside vulnetixDir, creating the directory if needed.
func Save(vulnetixDir string, m *Memory) error {
	if err := os.MkdirAll(vulnetixDir, 0o755); err != nil {
		return fmt.Errorf("failed to create %s: %w", vulnetixDir, err)
	}

	path := filepath.Join(vulnetixDir, FileName)
	data, err := yaml.Marshal(m)
	if err != nil {
		return fmt.Errorf("failed to marshal memory: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	return nil
}

// RecordScan prepends rec to History, sets LastScan, and trims history to maxHistory.
// If rec.Timestamp is empty it is set to the current UTC time.
func (m *Memory) RecordScan(rec ScanRecord) {
	if rec.Timestamp == "" {
		rec.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	m.LastScan = &rec
	m.History = append([]ScanRecord{rec}, m.History...)
	if len(m.History) > maxHistory {
		m.History = m.History[:maxHistory]
	}
}
