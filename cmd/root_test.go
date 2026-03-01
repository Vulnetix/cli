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
		name                 string
		args                 []string
		expectError          bool
		expectOutputContains string
		expectErrorContains  string
		setupEnv             map[string]string // Added setupEnv field
	}{
		// Info task (default, no --org-id required)
		{
			name:                 "Default info task",
			args:                 []string{},
			expectError:          false,
			expectOutputContains: "Authentication Sources:",
		},
		// Version Command Test
		{
			name:                 "Version command",
			args:                 []string{"version"},
			expectError:          false,
			expectOutputContains: "Vulnetix CLI v",
		},
	}

	for _, tt := range tests {
		// Reset global variables before each test
		orgID = ""
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
