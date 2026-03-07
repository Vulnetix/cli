package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPurlCommand(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		errContains string
	}{
		{
			name:        "no args",
			args:        []string{"vdb", "purl"},
			expectError: true,
			errContains: "accepts 1 arg(s)",
		},
		{
			name:        "too many args",
			args:        []string{"vdb", "purl", "pkg:npm/a", "pkg:npm/b"},
			expectError: true,
			errContains: "accepts 1 arg(s)",
		},
		{
			name:        "invalid PURL - no scheme",
			args:        []string{"vdb", "purl", "npm/express"},
			expectError: true,
			errContains: "missing 'pkg:' scheme",
		},
		{
			name:        "invalid PURL - empty name",
			args:        []string{"vdb", "purl", "pkg:npm/"},
			expectError: true,
			errContains: "empty name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := executeCommand(t, rootCmd, tt.args...)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
