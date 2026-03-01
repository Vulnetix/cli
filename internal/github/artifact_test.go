package github

import (
	"archive/zip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestSanitizeArtifactName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"normal name", "my-artifact", "my-artifact"},
		{"with spaces", "my artifact", "my_artifact"},
		{"with path separator", "path/to/artifact", "path_to_artifact"},
		{"with dots", "../artifact", "_artifact"},
		{"with special chars", "artifact@#$%", "artifact____"},
		{"empty after sanitization", "...", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeArtifactName(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeArtifactName(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestListArtifacts(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check auth header
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Return mock artifact list
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"total_count": 2,
			"artifacts": [
				{
					"id": 1,
					"name": "artifact1",
					"size_in_bytes": 1024,
					"url": "https://api.github.com/repos/test/repo/actions/artifacts/1",
					"archive_download_url": "https://api.github.com/repos/test/repo/actions/artifacts/1/zip"
				},
				{
					"id": 2,
					"name": "artifact2",
					"size_in_bytes": 2048,
					"url": "https://api.github.com/repos/test/repo/actions/artifacts/2",
					"archive_download_url": "https://api.github.com/repos/test/repo/actions/artifacts/2/zip"
				}
			]
		}`))
	}))
	defer server.Close()

	collector := NewArtifactCollector("test-token", server.URL, "test/repo", "123")

	ctx := context.Background()
	artifacts, err := collector.ListArtifacts(ctx)
	if err != nil {
		t.Fatalf("ListArtifacts failed: %v", err)
	}

	if len(artifacts) != 2 {
		t.Errorf("Expected 2 artifacts, got %d", len(artifacts))
	}

	if artifacts[0].Name != "artifact1" {
		t.Errorf("Expected artifact name 'artifact1', got '%s'", artifacts[0].Name)
	}

	if artifacts[1].SizeInBytes != 2048 {
		t.Errorf("Expected artifact size 2048, got %d", artifacts[1].SizeInBytes)
	}
}

func TestListArtifacts_NoToken(t *testing.T) {
	collector := NewArtifactCollector("", "https://api.github.com", "test/repo", "123")

	ctx := context.Background()
	_, err := collector.ListArtifacts(ctx)
	if err == nil {
		t.Error("Expected error when token is missing, got nil")
	}

	if !strings.Contains(err.Error(), "GitHub token is required") {
		t.Errorf("Expected 'GitHub token is required' error, got: %v", err)
	}
}

func TestExtractZip_ZipSlipProtection(t *testing.T) {
	// Create a malicious zip file with path traversal
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "malicious.zip")

	// Create a zip with path traversal attempt
	zipFile, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("Failed to create zip file: %v", err)
	}

	w := zip.NewWriter(zipFile)

	// Try to create entry with ".." in path
	_, err = w.Create("../../etc/passwd")
	if err != nil {
		zipFile.Close()
		t.Fatalf("Failed to create zip entry: %v", err)
	}

	w.Close()
	zipFile.Close()

	// Attempt to extract
	destDir := filepath.Join(tmpDir, "extracted")
	err = extractZip(zipPath, destDir)

	// Should fail due to path traversal protection
	if err == nil {
		t.Error("Expected error for zip slip attempt, got nil")
	}

	if !strings.Contains(err.Error(), "unsafe path") && !strings.Contains(err.Error(), "outside destination") {
		t.Errorf("Expected path traversal error, got: %v", err)
	}
}

func TestExtractZip_ValidZip(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "valid.zip")

	// Create a valid zip file
	zipFile, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("Failed to create zip file: %v", err)
	}

	w := zip.NewWriter(zipFile)

	// Add a test file
	fileWriter, err := w.Create("test.txt")
	if err != nil {
		zipFile.Close()
		t.Fatalf("Failed to create zip entry: %v", err)
	}

	_, err = fileWriter.Write([]byte("test content"))
	if err != nil {
		zipFile.Close()
		t.Fatalf("Failed to write zip entry: %v", err)
	}

	w.Close()
	zipFile.Close()

	// Extract
	destDir := filepath.Join(tmpDir, "extracted")
	err = extractZip(zipPath, destDir)
	if err != nil {
		t.Fatalf("extractZip failed: %v", err)
	}

	// Verify extracted file
	extractedFile := filepath.Join(destDir, "test.txt")
	content, err := os.ReadFile(extractedFile)
	if err != nil {
		t.Fatalf("Failed to read extracted file: %v", err)
	}

	if string(content) != "test content" {
		t.Errorf("Expected 'test content', got '%s'", string(content))
	}

	// Check file permissions are safe
	info, err := os.Stat(extractedFile)
	if err != nil {
		t.Fatalf("Failed to stat extracted file: %v", err)
	}

	mode := info.Mode()
	if mode != 0644 {
		t.Errorf("Expected file mode 0644, got %v", mode)
	}
}

func TestDownloadArtifact_SizeLimit(t *testing.T) {
	// Create a test server that returns artifact data
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.WriteHeader(http.StatusOK)
		// Write some data
		w.Write(make([]byte, 1024))
	}))
	defer server.Close()

	collector := NewArtifactCollector("test-token", server.URL, "test/repo", "123")

	// Create artifact with size exceeding limit
	artifact := Artifact{
		ID:                 1,
		Name:               "large-artifact",
		SizeInBytes:        maxArtifactSize + 1,
		ArchiveDownloadURL: server.URL,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		ExpiresAt:          time.Now().Add(24 * time.Hour),
	}

	ctx := context.Background()
	_, err := collector.DownloadArtifact(ctx, artifact)

	if err == nil {
		t.Error("Expected error for artifact exceeding size limit, got nil")
	}

	if !strings.Contains(err.Error(), "exceeds maximum allowed size") {
		t.Errorf("Expected size limit error, got: %v", err)
	}
}

func TestDownloadArtifact_Success(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a valid zip file to serve
	zipPath := filepath.Join(tmpDir, "artifact.zip")
	zipFile, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("Failed to create zip file: %v", err)
	}

	w := zip.NewWriter(zipFile)
	fileWriter, err := w.Create("test.txt")
	if err != nil {
		zipFile.Close()
		t.Fatalf("Failed to create zip entry: %v", err)
	}
	fileWriter.Write([]byte("test content"))
	w.Close()
	zipFile.Close()

	// Read the zip file
	zipData, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatalf("Failed to read zip file: %v", err)
	}

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.WriteHeader(http.StatusOK)
		w.Write(zipData)
	}))
	defer server.Close()

	collector := NewArtifactCollector("test-token", server.URL, "test/repo", "123")

	artifact := Artifact{
		ID:                 1,
		Name:               "test-artifact",
		SizeInBytes:        int64(len(zipData)),
		ArchiveDownloadURL: server.URL,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		ExpiresAt:          time.Now().Add(24 * time.Hour),
	}

	ctx := context.Background()
	extractDir, err := collector.DownloadArtifact(ctx, artifact)
	if err != nil {
		t.Fatalf("DownloadArtifact failed: %v", err)
	}
	defer os.RemoveAll(extractDir)

	// Verify extracted file
	extractedFile := filepath.Join(extractDir, "test.txt")
	content, err := os.ReadFile(extractedFile)
	if err != nil {
		t.Fatalf("Failed to read extracted file: %v", err)
	}

	if string(content) != "test content" {
		t.Errorf("Expected 'test content', got '%s'", string(content))
	}
}
