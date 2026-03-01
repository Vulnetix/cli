package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/vulnetix/cli/internal/testutils"
)

// executeCommand executes a cobra command and captures its output.
// It also mocks os.Exit to prevent the test from exiting.
func executeCommand(t *testing.T, cmd *cobra.Command, args ...string) (output string, err error) {
	t.Helper()

	// Capture stdout and stderr
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stdout = w
	os.Stderr = w

	outC := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		outC <- buf.String()
	}()

	// Mock os.Exit
	oldOsExit := exit
	exit = func(code int) {
		// We don't want to actually exit during tests, so we panic and recover.
		// The executeCommand defer function will catch this panic.
		panic(fmt.Sprintf("os.Exit called with code %d", code))
	}

	defer func() {
		// Restore os.Exit
		exit = oldOsExit

		// Restore stdout and stderr
		w.Close()
		os.Stdout = oldStdout
		os.Stderr = oldStderr
		output = <-outC

		// Recover from panic if os.Exit was called
		if r := recover(); r != nil {
			if s, ok := r.(string); ok && strings.HasPrefix(s, "os.Exit called with code") {
				err = fmt.Errorf(s) // Convert panic to error
			} else {
				panic(r) // Not our panic, re-panic
			}
		}
	}()

	cmd.SetArgs(args)
	err = cmd.Execute()

	return output, err
}

func TestRootCommand(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		expectOutputContains string
		expectErrorContains string
		setupEnv map[string]string // Added setupEnv field
	}{
		// Org ID Validation Tests
		{
			name:        "Valid UUID",
			args:        []string{"--org-id", "123e4567-e89b-12d3-a456-426614174000"},
			expectError: false,
			expectOutputContains: "Organization ID: 123e4567-e89b-12d3-a456-426614174000",
		},
		{
			name:        "Invalid UUID",
			args:        []string{"--org-id", "invalid-uuid"},
			expectError: true,
			expectErrorContains: "--org-id must be a valid UUID",
		},
		{
			name:        "Missing org-id",
			args:        []string{},
			expectError: true,
			expectErrorContains: "--org-id is required",
		},

		// Task Validation Tests
		{
			name:        "Valid scan task",
			args:        []string{"--org-id", "123e4567-e89b-12d3-a456-426614174000", "--task", "scan"},
			expectError: false,
			expectOutputContains: "Task: scan",
		},
		{
			name:        "Valid release task",
			args:        []string{"--org-id", "123e4567-e89b-12d3-a456-426614174000", "--task", "release", "--production-branch", "main", "--release-branch", "dev"},
			expectError: false,
			expectOutputContains: "Task: release",
			setupEnv: map[string]string{
				"GITHUB_RUN_ID": "123456789",
				"GITHUB_REPOSITORY": "octocat/Spoon-Knife",
			},
		},
		{
			name:        "Invalid task",
			args:        []string{"--org-id", "123e4567-e89b-12d3-a456-426614174000", "--task", "invalid"},
			expectError: true,
			expectErrorContains: "unsupported task: invalid",
		},

		// Release Task Specific Validations
		{
			name:        "Release task missing release-branch",
			args:        []string{"--org-id", "123e4567-e89b-12d3-a456-426614174000", "--task", "release", "--production-branch", "main"},
			expectError: true,
			expectErrorContains: "release branch is required for release readiness assessment",
			setupEnv: map[string]string{
				"GITHUB_RUN_ID": "123456789",
				"GITHUB_REPOSITORY": "octocat/Spoon-Knife",
			},
		},
		{
			name:        "Release task with valid branches",
			args:        []string{"--org-id", "123e4567-e89b-12d3-a456-426614174000", "--task", "release", "--production-branch", "main", "--release-branch", "dev"},
			expectError: false,
			expectOutputContains: "Task: release",
			setupEnv: map[string]string{
				"GITHUB_RUN_ID": "123456789",
				"GITHUB_REPOSITORY": "octocat/Spoon-Knife",
			},
		},

		// Optional Flags Tests
		{
			name:        "With project and product name",
			args:        []string{"--org-id", "123e4567-e89b-12d3-a456-426614174000", "--project-name", "my-project", "--product-name", "my-product"},
			expectError: false,
			expectOutputContains: "Project: my-project",
		},
		{
			name:        "With team and group name",
			args:        []string{"--org-id", "123e4567-e89b-12d3-a456-426614174000", "--team-name", "my-team", "--group-name", "my-group"},
			expectError: false,
			expectOutputContains: "Team: my-team",
		},
		{
			name:        "With tags",
			args:        []string{"--org-id", "123e4567-e89b-12d3-a456-426614174000", "--tags", "[\"critical\", \"frontend\"]"},
			expectError: false,
			expectOutputContains: "Tags: [critical frontend]",
		},
		{
			name:        "With tools",
			args:        []string{"--org-id", "123e4567-e89b-12d3-a456-426614174000", "--tools", "- category: sast\n  artifact_name: results.sarif\n  format: SARIF"},
			expectError: false,
			expectOutputContains: "- sast (SARIF): results.sarif",
		},
		{
			name:        "With workflow-timeout",
			args:        []string{"--org-id", "123e4567-e89b-12d3-a456-426614174000", "--task", "release", "--production-branch", "main", "--release-branch", "dev", "--workflow-timeout", "60"},
			expectError: false,
			expectOutputContains: "Release Branch: dev",
			setupEnv: map[string]string{
				"GITHUB_RUN_ID": "123456789",
				"GITHUB_REPOSITORY": "octocat/Spoon-Knife",
			},
		},

		// Version Command Test
		{
			name:        "Version command",
			args:        []string{"version"},
			expectError: false,
			expectOutputContains: "Vulnetix CLI v",
		},
	}

	for _, tt := range tests {
		// Reset global variables before each test
		orgID = ""
		task = "scan"
		projectName = ""
		productName = ""
		teamName = ""
		groupName = ""
		tags = ""
		tools = ""
		productionBranch = "main"
		releaseBranch = ""
		workflowTimeout = 30

		// Setup environment variables if needed
		var cleanupEnv func()
		if tt.setupEnv != nil {
			cleanupEnv = testutils.SetEnv(t, tt.setupEnv)
		}

		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if cleanupEnv != nil {
					cleanupEnv()
				}
			}()

			// Use the actual rootCmd for testing
			output, err := executeCommand(t, rootCmd, tt.args...)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectErrorContains)
			} else {
				assert.NoError(t, err)
				assert.Contains(t, output, tt.expectOutputContains)
			}
		})
	}
}

// exit is a variable that can be overridden for testing purposes
var exit = os.Exit
