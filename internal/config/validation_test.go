package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateTask(t *testing.T) {
	tests := []struct {
		name    string
		task    string
		expectedErr string
	}{
		{name: "Valid scan task", task: "scan", expectedErr: ""},
		{name: "Valid release task", task: "release", expectedErr: ""},
		{name: "Valid report task", task: "report", expectedErr: ""},
		{name: "Valid triage task", task: "triage", expectedErr: ""},
		{name: "Invalid task", task: "invalid", expectedErr: "unsupported task"},
		{name: "Empty task", task: "", expectedErr: ""}, // Default to scan, no error
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateTask(tt.task) // ValidateTask returns (TaskType, error)
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			}
		})
	}
}

func TestValidateReleaseReadiness(t *testing.T) {
	tests := []struct {
		name        string
		config      *VulnetixConfig
		expectedErr string
	}{
		{
			name: "Valid release configuration and CI context",
			config: &VulnetixConfig{
				Task: TaskRelease,
				Release: ReleaseConfig{
					ProductionBranch: "main",
					ReleaseBranch:    "release",
				},
				CI: CIContext{
					RunID:      "123",
					Repository: "owner/repo",
				},
			},
			expectedErr: "",
		},
		{
			name: "Missing production branch in release config",
			config: &VulnetixConfig{
				Task: TaskRelease,
				Release: ReleaseConfig{
					ReleaseBranch: "release",
				},
				CI: CIContext{
					RunID:      "123",
					Repository: "owner/repo",
				},
			},
			expectedErr: "production branch is required for release readiness assessment",
		},
		{
			name: "Missing release branch in release config",
			config: &VulnetixConfig{
				Task: TaskRelease,
				Release: ReleaseConfig{
					ProductionBranch: "main",
				},
				CI: CIContext{
					RunID:      "123",
					Repository: "owner/repo",
				},
			},
			expectedErr: "release branch is required for release readiness assessment",
		},
		{
			name: "Missing CI run ID",
			config: &VulnetixConfig{
				Task: TaskRelease,
				Release: ReleaseConfig{
					ProductionBranch: "main",
					ReleaseBranch:    "release",
				},
				CI: CIContext{
					Repository: "owner/repo",
				},
			},
			expectedErr: "CI run ID is required for artifact linking",
		},
		{
			name: "Missing CI repository",
			config: &VulnetixConfig{
				Task: TaskRelease,
				Release: ReleaseConfig{
					ProductionBranch: "main",
					ReleaseBranch:    "release",
				},
				CI: CIContext{
					RunID: "123",
				},
			},
			expectedErr: "CI repository is required for artifact scoping",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.ValidateReleaseReadiness()
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			}
		})
	}
}

func TestIsReleaseTask(t *testing.T) {
	tests := []struct {
		name     string
		config   *VulnetixConfig // Use VulnetixConfig
		expected bool
	}{
		{name: "Is release task", config: &VulnetixConfig{Task: TaskRelease}, expected: true},
		{name: "Is not release task (scan)", config: &VulnetixConfig{Task: TaskScan}, expected: false},
		{name: "Is not release task (report)", config: &VulnetixConfig{Task: TaskReport}, expected: false},
		{name: "Is not release task (triage)", config: &VulnetixConfig{Task: TaskTriage}, expected: false},
		{name: "Empty task", config: &VulnetixConfig{Task: ""}, expected: false},
		{name: "Invalid task", config: &VulnetixConfig{Task: "invalid"}, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.config.IsReleaseTask()) // Call method on config instance
		})
	}
}
