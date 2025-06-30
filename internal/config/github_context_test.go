package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vulnetix/vulnetix/internal/testutils"
)

func TestLoadGitHubContext(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		expected GitHubContext
	}{
		{
			name: "Complete GitHub environment simulation",
			env: testutils.GitHubContextFixture(),
			expected: GitHubContext{
				Actor:            "octocat",
				Repository:       "octocat/Spoon-Knife",
				RepositoryOwner:  "octocat",
				RunID:            "123456789",
				RunNumber:        "1",
				JobID:            "build",
				WorkflowRef:      "", // Not set in fixture
				WorkflowSHA:      "", // Not set in fixture
				Workspace:        "", // Not set in fixture
				SHA:              "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
				RefName:          "", // Not set in fixture
				RefType:          "", // Not set in fixture
				HeadRef:          "", // Not set in fixture
				BaseRef:          "", // Not set in fixture
				EventName:        "push",
				EventPath:        "", // Not set in fixture
				ActionPath:       "", // Not set in fixture
				ActionRepository: "", // Not set in fixture
				ServerURL:        "", // Not set in fixture
				APIURL:           "", // Not set in fixture
				GraphQLURL:       "", // Not set in fixture
				Token:            "", // Not set in fixture
				RetentionDays:    "", // Not set in fixture
				RunnerOS:         "Linux",
				RunnerArch:       "X64",
				RunnerName:       "", // Not set in fixture
				RunnerTemp:       "/tmp",
				RunnerToolCache:  "/opt/hostedtoolcache",
			},
		},
		{
			name: "Partial environment variables",
			env: map[string]string{
				"GITHUB_REPOSITORY": "partial/repo",
				"GITHUB_SHA":        "partialsha",
			},
			expected: GitHubContext{
				Repository: "partial/repo",
				SHA:        "partialsha",
			},
		},
		{
			name: "Missing environment variables",
			env: map[string]string{},
			expected: GitHubContext{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanup := testutils.SetEnv(t, tt.env)
			defer cleanup()

			actual := LoadGitHubContext()
			assert.Equal(t, tt.expected, actual)
		})
	}
}

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
