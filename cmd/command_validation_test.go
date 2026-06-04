package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCompletionCommandRejectsUnknownShell(t *testing.T) {
	_, err := executeCommand(t, rootCmd, "completion", "nope", "--no-analytics")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown shell")
	assert.Contains(t, err.Error(), "bash, zsh, fish, or powershell")
}

func TestLicenseCommandRejectsInvalidMode(t *testing.T) {
	resetLicenseValidationFlags(t)

	_, err := executeCommand(t, rootCmd,
		"license",
		"--path", t.TempDir(),
		"--mode", "nope",
		"--no-progress",
		"--no-analytics",
	)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "--mode must be one of: inclusive, individual")
}

func TestLicenseCommandRejectsInvalidOutput(t *testing.T) {
	resetLicenseValidationFlags(t)

	_, err := executeCommand(t, rootCmd,
		"license",
		"--path", t.TempDir(),
		"--output", "xml",
		"--no-progress",
		"--no-analytics",
	)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "--output must be one of: pretty, json, json-spdx")
}

func TestLicenseFromMemoryRejectsSPDXOutput(t *testing.T) {
	resetLicenseValidationFlags(t)

	_, err := executeCommand(t, rootCmd,
		"license",
		"--from-memory",
		"--output", "json-spdx",
		"--path", t.TempDir(),
		"--no-progress",
		"--no-analytics",
	)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "--output json-spdx is not supported with --from-memory")
}

func resetLicenseValidationFlags(t *testing.T) {
	t.Helper()

	defaults := map[string]string{
		"path":         ".",
		"depth":        "3",
		"mode":         "inclusive",
		"allow":        "",
		"allow-file":   "",
		"severity":     "",
		"output":       "",
		"from-memory":  "false",
		"dry-run":      "false",
		"results-only": "false",
	}
	for name, value := range defaults {
		assert.NoError(t, licenseCmd.Flags().Set(name, value))
	}
}

func TestNormalizeAPIVersionDefaultsToV2(t *testing.T) {
	assert.Equal(t, "/v2", normalizeAPIVersion(""))
	assert.Equal(t, "/v2", normalizeAPIVersion("v2"))
	assert.Equal(t, "/v2", normalizeAPIVersion("/V2/"))
	assert.Equal(t, "/v1", normalizeAPIVersion("v1"))
}
