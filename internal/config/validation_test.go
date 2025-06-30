package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vulnetix/vulnetix/internal/testutils"
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
		{name: "Invalid task", task: "invalid", expectedErr: "invalid task type"},
		{name: "Empty task", task: "", expectedErr: "task type cannot be empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTask(tt.task)
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
	// Mock GitHub context for testing
	setupGitHubContext := func(t *testing.T, env map[string]string) func() {
		return testutils.SetEnv(t, env)
	}

	tests := []struct {
		name        string
		config      *Config
		env         map[string]string
		expectedErr string
	}{
		{
			name: "Valid release configuration and GitHub context",
			config: &Config{
				Task: "release",
				Release: &ReleaseConfig{
					TargetBranch: "main",
					GitHubContext: &GitHubContext{
						WorkflowRunID: "123",
						Repository:    "owner/repo",
						Ref:           "refs/heads/main",
						SHA:           "abc",
					},
				},
			},
			env: testutils.GitHubContextFixture(),
			expectedErr: "",
		},
		{
			name: "Missing target branch in release config",
			config: &Config{
				Task: "release",
				Release: &ReleaseConfig{
					GitHubContext: &GitHubContext{
						WorkflowRunID: "123",
						Repository:    "owner/repo",
						Ref:           "refs/heads/main",
						SHA:           "abc",
					},
				},
			},
			env: testutils.GitHubContextFixture(),
			expectedErr: "release.target_branch cannot be empty",
		},
		{
			name: "Missing GitHub context in release config",
			config: &Config{
				Task: "release",
				Release: &ReleaseConfig{
					TargetBranch: "main",
				},
			},
			env: testutils.GitHubContextFixture(),
			expectedErr: "release.github_context cannot be empty",
		},
		{
			name: "Missing GITHUB_ACTIONS env var",
			config: &Config{
				Task: "release",
				Release: &ReleaseConfig{
					TargetBranch: "main",
					GitHubContext: &GitHubContext{
						WorkflowRunID: "123",
						Repository:    "owner/repo",
						Ref:           "refs/heads/main",
						SHA:           "abc",
					},
				},
			},
			env: map[string]string{
				"GITHUB_REPOSITORY": "owner/repo",
				"GITHUB_REF":        "refs/heads/main",
				"GITHUB_SHA":        "abc",
			},
			expectedErr: "GITHUB_ACTIONS environment variable must be 'true' for release tasks",
		},
		{
			name: "GITHUB_ACTIONS not true",
			config: &Config{
				Task: "release",
				Release: &ReleaseConfig{
					TargetBranch: "main",
					GitHubContext: &GitHubContext{
						WorkflowRunID: "123",
						Repository:    "owner/repo",
						Ref:           "refs/heads/main",
						SHA:           "abc",
					},
				},
			},
			env: map[string]string{
				"GITHUB_ACTIONS":    "false",
				"GITHUB_REPOSITORY": "owner/repo",
				"GITHUB_REF":        "refs/heads/main",
				"GITHUB_SHA":        "abc",
			},
			expectedErr: "GITHUB_ACTIONS environment variable must be 'true' for release tasks",
		},
		{
			name: "Missing GITHUB_REPOSITORY env var",
			config: &Config{
				Task: "release",
				Release: &ReleaseConfig{
					TargetBranch: "main",
					GitHubContext: &GitHubContext{
						WorkflowRunID: "123",
						Repository:    "owner/repo",
						Ref:           "refs/heads/main",
						SHA:           "abc",
					},
				},
			},
			env: map[string]string{
				"GITHUB_ACTIONS": "true",
				"GITHUB_REF":     "refs/heads/main",
				"GITHUB_SHA":     "abc",
			},
			expectedErr: "GITHUB_REPOSITORY environment variable cannot be empty for release tasks",
		},
		{
			name: "Missing GITHUB_REF env var",
			config: &Config{
				Task: "release",
				Release: &ReleaseConfig{
					TargetBranch: "main",
					GitHubContext: &GitHubContext{
						WorkflowRunID: "123",
						Repository:    "owner/repo",
						Ref:           "refs/heads/main",
						SHA:           "abc",
					},
				},
			},
			env: map[string]string{
				"GITHUB_ACTIONS":    "true",
				"GITHUB_REPOSITORY": "owner/repo",
				"GITHUB_SHA":        "abc",
			},
			expectedErr: "GITHUB_REF environment variable cannot be empty for release tasks",
		},
		{
			name: "Missing GITHUB_SHA env var",
			config: &Config{
				Task: "release",
				Release: &ReleaseConfig{
					TargetBranch: "main",
					GitHubContext: &GitHubContext{
						WorkflowRunID: "123",
						Repository:    "owner/repo",
						Ref:           "refs/heads/main",
						SHA:           "abc",
					},
				},
			},
			env: map[string]string{
				"GITHUB_ACTIONS":    "true",
				"GITHUB_REPOSITORY": "owner/repo",
				"GITHUB_REF":        "refs/heads/main",
			},
			expectedErr: "GITHUB_SHA environment variable cannot be empty for release tasks",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanup := setupGitHubContext(t, tt.env)
			defer cleanup()

			err := ValidateReleaseReadiness(tt.config)
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
		task     string
		expected bool
	}{
		{name: "Is release task", task: "release", expected: true},
		{name: "Is not release task (scan)", task: "scan", expected: false},
		{name: "Is not release task (report)", task: "report", expected: false},
		{name: "Is not release task (triage)", task: "triage", expected: false},
		{name: "Empty task", task: "", expected: false},
		{name: "Invalid task", task: "invalid", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsReleaseTask(tt.task))
		})
	}
}
