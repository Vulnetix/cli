package github

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	// maxArtifactSize is the maximum size for an artifact download (1GB)
	maxArtifactSize = 1024 * 1024 * 1024
	// artifactDownloadTimeout is the timeout for downloading artifacts
	artifactDownloadTimeout = 10 * time.Minute
)

var (
	// artifactNameRegex matches safe characters for artifact names
	artifactNameRegex = regexp.MustCompile(`[^a-zA-Z0-9\-_\.]`)
)

// Artifact represents a GitHub Actions artifact
type Artifact struct {
	ID                 int64     `json:"id"`
	NodeID             string    `json:"node_id"`
	Name               string    `json:"name"`
	SizeInBytes        int64     `json:"size_in_bytes"`
	URL                string    `json:"url"`
	ArchiveDownloadURL string    `json:"archive_download_url"`
	Expired            bool      `json:"expired"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
	ExpiresAt          time.Time `json:"expires_at"`
}

// ArtifactsResponse represents the GitHub API response for artifacts
type ArtifactsResponse struct {
	TotalCount int        `json:"total_count"`
	Artifacts  []Artifact `json:"artifacts"`
}

// ArtifactMetadata contains metadata about the workflow and artifacts
type ArtifactMetadata struct {
	Repository      string            `json:"repository"`
	RepositoryOwner string            `json:"repository_owner"`
	RunID           string            `json:"run_id"`
	RunNumber       string            `json:"run_number"`
	WorkflowName    string            `json:"workflow_name"`
	JobName         string            `json:"job"`
	SHA             string            `json:"sha"`
	RefName         string            `json:"ref_name"`
	RefType         string            `json:"ref_type"`
	EventName       string            `json:"event_name"`
	Actor           string            `json:"actor"`
	ServerURL       string            `json:"server_url"`
	APIURL          string            `json:"api_url"`
	Artifacts       []string          `json:"artifacts"`
	ExtraEnvVars    map[string]string `json:"extra_env_vars,omitempty"`
}

// ArtifactCollector handles collection of GitHub Actions artifacts
type ArtifactCollector struct {
	token      string
	apiURL     string
	repository string
	runID      string
	client     *http.Client
}

// NewArtifactCollector creates a new artifact collector
func NewArtifactCollector(token, apiURL, repository, runID string) *ArtifactCollector {
	return &ArtifactCollector{
		token:      token,
		apiURL:     apiURL,
		repository: repository,
		runID:      runID,
		client: &http.Client{
			Timeout: artifactDownloadTimeout,
		},
	}
}

// sanitizeArtifactName sanitizes artifact names to prevent path traversal
func sanitizeArtifactName(name string) string {
	// Remove any path separators and special characters
	sanitized := artifactNameRegex.ReplaceAllString(name, "_")
	// Remove leading dots to prevent hidden files
	sanitized = strings.TrimLeft(sanitized, ".")
	return sanitized
}

// CollectMetadata collects metadata from GitHub Actions environment
func CollectMetadata(artifactNames []string) *ArtifactMetadata {
	// Collect standard GitHub Actions environment variables
	metadata := &ArtifactMetadata{
		Repository:      getEnv("GITHUB_REPOSITORY"),
		RepositoryOwner: getEnv("GITHUB_REPOSITORY_OWNER"),
		RunID:           getEnv("GITHUB_RUN_ID"),
		RunNumber:       getEnv("GITHUB_RUN_NUMBER"),
		WorkflowName:    getEnv("GITHUB_WORKFLOW"),
		JobName:         getEnv("GITHUB_JOB"),
		SHA:             getEnv("GITHUB_SHA"),
		RefName:         getEnv("GITHUB_REF_NAME"),
		RefType:         getEnv("GITHUB_REF_TYPE"),
		EventName:       getEnv("GITHUB_EVENT_NAME"),
		Actor:           getEnv("GITHUB_ACTOR"),
		ServerURL:       getEnv("GITHUB_SERVER_URL"),
		APIURL:          getEnv("GITHUB_API_URL"),
		Artifacts:       artifactNames,
	}

	// Collect additional environment variables that might be useful
	extraVars := make(map[string]string)
	extraEnvKeys := []string{
		"GITHUB_HEAD_REF",
		"GITHUB_BASE_REF",
		"GITHUB_REF",
		"GITHUB_WORKFLOW_REF",
		"GITHUB_WORKFLOW_SHA",
		"GITHUB_RUN_ATTEMPT",
		"RUNNER_OS",
		"RUNNER_ARCH",
		"RUNNER_NAME",
	}

	for _, key := range extraEnvKeys {
		if val := getEnv(key); val != "" {
			extraVars[key] = val
		}
	}

	if len(extraVars) > 0 {
		metadata.ExtraEnvVars = extraVars
	}

	return metadata
}

// ListArtifacts lists all artifacts for the current workflow run
func (c *ArtifactCollector) ListArtifacts(ctx context.Context) ([]Artifact, error) {
	if c.token == "" {
		return nil, fmt.Errorf("GitHub token is required. Set GITHUB_TOKEN environment variable")
	}

	url := fmt.Sprintf("%s/repos/%s/actions/runs/%s/artifacts", c.apiURL, c.repository, c.runID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch artifacts: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, string(body))
	}

	var artifactsResp ArtifactsResponse
	if err := json.NewDecoder(resp.Body).Decode(&artifactsResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return artifactsResp.Artifacts, nil
}

// DownloadArtifact downloads an artifact and extracts it to a temporary directory
func (c *ArtifactCollector) DownloadArtifact(ctx context.Context, artifact Artifact) (string, error) {
	if c.token == "" {
		return "", fmt.Errorf("GitHub token is required")
	}

	// Check artifact size
	if artifact.SizeInBytes > maxArtifactSize {
		return "", fmt.Errorf("artifact size (%d bytes) exceeds maximum allowed size (%d bytes)", artifact.SizeInBytes, maxArtifactSize)
	}

	// Sanitize artifact name for directory pattern
	sanitizedName := sanitizeArtifactName(artifact.Name)
	if sanitizedName == "" {
		sanitizedName = "artifact"
	}

	// Create temporary directory for extraction
	tmpDir, err := os.MkdirTemp("", fmt.Sprintf("artifact-%s-*", sanitizedName))
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Download artifact
	req, err := http.NewRequestWithContext(ctx, "GET", artifact.ArchiveDownloadURL, nil)
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("failed to create download request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := c.client.Do(req)
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("failed to download artifact: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("download failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Save to temporary zip file
	zipPath := filepath.Join(tmpDir, "artifact.zip")
	zipFile, err := os.Create(zipPath)
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("failed to create zip file: %w", err)
	}

	// Limit the reader to prevent resource exhaustion
	limitedReader := io.LimitReader(resp.Body, maxArtifactSize)
	_, err = io.Copy(zipFile, limitedReader)
	zipFile.Close()
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("failed to save artifact: %w", err)
	}

	// Extract zip
	if err := extractZip(zipPath, tmpDir); err != nil {
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("failed to extract artifact: %w", err)
	}

	// Remove the zip file
	os.Remove(zipPath)

	return tmpDir, nil
}

// extractZip extracts a zip file to the specified directory
func extractZip(zipPath, destDir string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer reader.Close()

	// Clean the destination directory path for comparison
	destDir = filepath.Clean(destDir)

	for _, file := range reader.File {
		// Prevent Zip Slip vulnerability by checking for path traversal
		if strings.Contains(file.Name, "..") {
			return fmt.Errorf("zip file contains potentially unsafe path: %s", file.Name)
		}

		// Join and clean the path
		path := filepath.Join(destDir, file.Name)
		path = filepath.Clean(path)

		// Verify the resulting path is within destDir
		if !strings.HasPrefix(path, destDir+string(os.PathSeparator)) && path != destDir {
			return fmt.Errorf("zip file contains entry outside destination directory: %s", file.Name)
		}

		if file.FileInfo().IsDir() {
			// Use safe permissions for directories
			if err := os.MkdirAll(path, 0755); err != nil {
				return err
			}
			continue
		}

		// Create parent directory with safe permissions
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}

		// Use safe permissions for files (0644 for regular files)
		destFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}

		fileReader, err := file.Open()
		if err != nil {
			destFile.Close()
			return err
		}

		// Copy with proper error handling
		_, copyErr := io.Copy(destFile, fileReader)

		// Close file reader first
		readerCloseErr := fileReader.Close()

		// Close destination file and check for close errors
		destCloseErr := destFile.Close()

		// Check all errors in order
		if copyErr != nil {
			return copyErr
		}
		if readerCloseErr != nil {
			return readerCloseErr
		}
		if destCloseErr != nil {
			return destCloseErr
		}
	}

	return nil
}

// getEnv gets an environment variable value
func getEnv(key string) string {
	return os.Getenv(key)
}
