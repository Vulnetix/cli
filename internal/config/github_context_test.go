package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetEnv(t *testing.T) {
	t.Run("Existing environment variable", func(t *testing.T) {
		os.Setenv("TEST_VAR", "test_value")
		defer os.Unsetenv("TEST_VAR")
		assert.Equal(t, "test_value", getEnv("TEST_VAR"))
	})

	t.Run("Non-existing environment variable", func(t *testing.T) {
		os.Unsetenv("NON_EXISTING_VAR")
		assert.Equal(t, "", getEnv("NON_EXISTING_VAR"))
	})
}
