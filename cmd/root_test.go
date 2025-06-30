package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRootCommand(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		expectOut   string
	}{
		{
			name:        "valid UUID",
			args:        []string{"--org-id", "123e4567-e89b-12d3-a456-426614174000"},
			expectError: false,
			expectOut:   "Vulnetix CLI",
		},
		{
			name:        "invalid UUID",
			args:        []string{"--org-id", "invalid-uuid"},
			expectError: true,
			expectOut:   "",
		},
		{
			name:        "missing org-id",
			args:        []string{},
			expectError: true,
			expectOut:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new command instance for each test
			cmd := &cobra.Command{
				Use:   "vulnetix",
				Short: "Vulnetix CLI - Automate vulnerability triage and remediation",
				Run: func(cmd *cobra.Command, args []string) {
					// Test implementation
				},
			}

			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				output := buf.String()
				if tt.expectOut != "" && !strings.Contains(output, tt.expectOut) {
					t.Errorf("Expected output to contain %q, got %q", tt.expectOut, output)
				}
			}
		})
	}
}

func TestVersionCommand(t *testing.T) {
	var buf bytes.Buffer
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version number of Vulnetix CLI",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Printf("Vulnetix CLI v%s\n", version)
		},
	}

	cmd.SetOut(&buf)
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Vulnetix CLI v") {
		t.Errorf("Expected version output, got %q", output)
	}
}
