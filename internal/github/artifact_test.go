package github

import (
	"os"
	"testing"
)

func TestCollectMetadata(t *testing.T) {
	// Set up test environment variables
	testEnvVars := map[string]string{
		"GITHUB_REPOSITORY":       "test/repo",
		"GITHUB_REPOSITORY_OWNER": "test",
		"GITHUB_RUN_ID":           "123456",
		"GITHUB_RUN_NUMBER":       "42",
		"GITHUB_WORKFLOW":         "Test Workflow",
		"GITHUB_JOB":              "test-job",
		"GITHUB_SHA":              "abc123",
		"GITHUB_REF_NAME":         "main",
		"GITHUB_REF_TYPE":         "branch",
		"GITHUB_EVENT_NAME":       "push",
		"GITHUB_ACTOR":            "testuser",
		"GITHUB_SERVER_URL":       "https://github.com",
		"GITHUB_API_URL":          "https://api.github.com",
		"GITHUB_HEAD_REF":         "feature-branch",
		"RUNNER_OS":               "Linux",
	}

	// Set environment variables
	for key, value := range testEnvVars {
		t.Setenv(key, value)
	}

	artifactNames := []string{"artifact1.zip", "artifact2.zip"}
	metadata := CollectMetadata(artifactNames)

	// Validate metadata
	if metadata.Repository != "test/repo" {
		t.Errorf("Expected repository 'test/repo', got '%s'", metadata.Repository)
	}

	if metadata.RepositoryOwner != "test" {
		t.Errorf("Expected repository owner 'test', got '%s'", metadata.RepositoryOwner)
	}

	if metadata.RunID != "123456" {
		t.Errorf("Expected run ID '123456', got '%s'", metadata.RunID)
	}

	if metadata.WorkflowName != "Test Workflow" {
		t.Errorf("Expected workflow name 'Test Workflow', got '%s'", metadata.WorkflowName)
	}

	if len(metadata.Artifacts) != 2 {
		t.Errorf("Expected 2 artifacts, got %d", len(metadata.Artifacts))
	}

	if metadata.ExtraEnvVars == nil {
		t.Error("Expected ExtraEnvVars to be populated")
	}

	if metadata.ExtraEnvVars["GITHUB_HEAD_REF"] != "feature-branch" {
		t.Errorf("Expected GITHUB_HEAD_REF 'feature-branch', got '%s'", metadata.ExtraEnvVars["GITHUB_HEAD_REF"])
	}
}

func TestCollectMetadata_EmptyEnvironment(t *testing.T) {
	// Clear all GitHub-related environment variables
	gitHubEnvVars := []string{
		"GITHUB_REPOSITORY",
		"GITHUB_REPOSITORY_OWNER",
		"GITHUB_RUN_ID",
		"GITHUB_RUN_NUMBER",
		"GITHUB_WORKFLOW",
		"GITHUB_JOB",
		"GITHUB_SHA",
		"GITHUB_REF_NAME",
		"GITHUB_REF_TYPE",
		"GITHUB_EVENT_NAME",
		"GITHUB_ACTOR",
		"GITHUB_SERVER_URL",
		"GITHUB_API_URL",
	}

	for _, key := range gitHubEnvVars {
		os.Unsetenv(key)
	}

	artifactNames := []string{"test.zip"}
	metadata := CollectMetadata(artifactNames)

	// Metadata should be created but with empty values
	if metadata.Repository != "" {
		t.Errorf("Expected empty repository, got '%s'", metadata.Repository)
	}

	if len(metadata.Artifacts) != 1 {
		t.Errorf("Expected 1 artifact, got %d", len(metadata.Artifacts))
	}

	if metadata.Artifacts[0] != "test.zip" {
		t.Errorf("Expected artifact 'test.zip', got '%s'", metadata.Artifacts[0])
	}
}

func TestNewArtifactCollector(t *testing.T) {
	token := "test-token"
	apiURL := "https://api.github.com"
	repository := "test/repo"
	runID := "123456"

	collector := NewArtifactCollector(token, apiURL, repository, runID)

	if collector.token != token {
		t.Errorf("Expected token '%s', got '%s'", token, collector.token)
	}

	if collector.apiURL != apiURL {
		t.Errorf("Expected apiURL '%s', got '%s'", apiURL, collector.apiURL)
	}

	if collector.repository != repository {
		t.Errorf("Expected repository '%s', got '%s'", repository, collector.repository)
	}

	if collector.runID != runID {
		t.Errorf("Expected runID '%s', got '%s'", runID, collector.runID)
	}

	if collector.client == nil {
		t.Error("Expected client to be initialized")
	}
}
