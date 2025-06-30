package testutils

import (
	"os"
	"strings"
)

// SetEnv temporarily sets environment variables for the duration of a test.
// It returns a cleanup function that restores the original environment variables.
func SetEnv(t interface {
	Helper()
	Setenv(key, value string)
}, env map[string]string) func() {
	t.Helper()
	originalEnv := make(map[string]string)

	for key, value := range env {
		originalEnv[key] = os.Getenv(key) // Store original value
		t.Setenv(key, value)              // Set new value for test
	}

	return func() {
		t.Helper()
		for key, originalValue := range originalEnv {
			if originalValue == "" {
				os.Unsetenv(key) // If original was empty, unset it
			} else {
				os.Setenv(key, originalValue) // Restore original value
			}
		}
	}
}

// ClearEnv clears a list of environment variables.
// It returns a cleanup function that restores the original environment variables.
func ClearEnv(t interface {
	Helper()
	Setenv(key, value string)
}, keys []string) func() {
	t.Helper()
	originalEnv := make(map[string]string)

	for _, key := range keys {
		originalEnv[key] = os.Getenv(key) // Store original value
		os.Unsetenv(key)                  // Clear for test
	}

	return func() {
		t.Helper()
		for key, originalValue := range originalEnv {
			if originalValue != "" {
				os.Setenv(key, originalValue) // Restore original value
			}
		}
	}
}

// GetEnvMapFromStrings converts a slice of "KEY=VALUE" strings into a map.
func GetEnvMapFromStrings(envStrings []string) map[string]string {
	envMap := make(map[string]string)
	for _, envStr := range envStrings {
		parts := strings.SplitN(envStr, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		} else if len(parts) == 1 {
			envMap[parts[0]] = "" // Handle cases like "KEY=" or "KEY"
		}
	}
	return envMap
}
