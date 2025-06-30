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
	exited := false
	exitCode := 0
	exit = func(code int) {
		exited = true
		exitCode = code
		panic("os.Exit was called") // Panic to stop execution, will be recovered
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
			if r.(string) != "os.Exit was called" {
				panic(r) // Not our panic, re-panic
			}
			if exited && exitCode != 0 {
				err = fmt.Errorf("command exited with code %d", exitCode)
			}
		}
	}()

	cmd.SetArgs(args)
	cmd.Execute()

	return output, err
}

func TestRootCommandOrgIDValidation(t *testing.T) {
	// Create a fresh root command for each test to avoid state leakage
	getFreshRootCmd := func() *cobra.Command {
		cmd := &cobra.Command{
			Use:   "vulnetix",
			Short: "Vulnetix CLI - Automate vulnerability triage and remediation",
			Run: func(cmd *cobra.Command, args []string) {
				// This will be the actual Run function from root.go
				// We need to call the original run function logic here.
				// For now, we'll just simulate it.
				// In a real scenario, you'd likely call the actual rootCmd.RunE or similar.
				// For this test, we're primarily testing the flag parsing and pre-run validation.
				// The actual logic of rootCmd.Run is complex and involves os.Exit, which is mocked.
				// So, we'll just let the flags be parsed and the validation logic in init() run.
				// The `executeCommand` helper will catch the os.Exit calls.
			},
		}
		// Re-initialize flags for the fresh command
		cmd.PersistentFlags().StringVar(&orgID, "org-id", "", "Organization ID (UUID) for Vulnetix operations (required)")
		cmd.MarkPersistentFlagRequired("org-id")
		cmd.PersistentFlags().StringVar(&task, "task", "scan", "Task to perform: scan, release, report, triage")
		cmd.PersistentFlags().StringVar(&productionBranch, "production-branch", "main", "Production branch name (for release task)")
		cmd.PersistentFlags().StringVar(&releaseBranch, "release-branch", "", "Release branch name (for release task)")
		cmd.PersistentFlags().IntVar(&workflowTimeout, "workflow-timeout", 30, "Timeout in minutes to wait for sibling job artifacts (for release task)")
		cmd.PersistentFlags().StringVar(&projectName, "project-name", "", "Project name for vulnerability management context")
		cmd.PersistentFlags().StringVar(&productName, "product-name", "", "Product name for vulnerability management context")
		cmd.PersistentFlags().StringVar(&teamName, "team-name", "", "Team name responsible for the project")
		cmd.PersistentFlags().StringVar(&groupName, "group-name", "", "Group name for organizational hierarchy")
		cmd.PersistentFlags().StringVar(&tags, "tags", "", "YAML list of tags for categorization (e.g., '["critical", "frontend", "api"]')")
		cmd.PersistentFlags().StringVar(&tools, "tools", "", "YAML array of tool configurations")

		// Add version command (needed for the actual rootCmd.Execute() to work as expected)
		versionCmd := &cobra.Command{
			Use:   "version",
			Short: "Print the version number of Vulnetix CLI",
			Run: func(cmd *cobra.Command, args []string) {
				fmt.Printf("Vulnetix CLI v%s\n", version)
			},
		}
		cmd.AddCommand(versionCmd)

		return cmd
	}

	tests := []struct {
		name        string
		args        []string
		expectError bool
		expectOutputContains string
	}{
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
			expectOutputContains: "--org-id must be a valid UUID",
		},
		{
			name:        "Missing org-id",
			args:        []string{},
			expectError: true,
			expectOutputContains: "Error: required flag(s) \"org-id\" not set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

			cmd := getFreshRootCmd()
			output, err := executeCommand(t, cmd, tt.args...)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, output, tt.expectOutputContains)
			} else {
				assert.NoError(t, err)
				assert.Contains(t, output, tt.expectOutputContains)
			}
		})
	}
}

// exit is a variable that can be overridden for testing purposes
var exit = os.Exit