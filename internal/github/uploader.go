package github

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/vulnetix/cli/internal/auth"
)

var (
	// txnIDRegex validates transaction ID format
	txnIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
)

// TransactionRequest represents the initial transaction creation request
type TransactionRequest struct {
	Meta      *ArtifactMetadata `json:"_meta"`
	Artifacts []string          `json:"artifacts"`
}

// TransactionResponse represents the response from transaction creation
type TransactionResponse struct {
	TxnID   string `json:"txnid"`
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// ArtifactUploadResponse represents the response from artifact upload
type ArtifactUploadResponse struct {
	UUID      string `json:"uuid"`
	QueuePath string `json:"queue_path"`
	Success   bool   `json:"success"`
	Message   string `json:"message,omitempty"`
}

// StatusResponse represents the status check response
type StatusResponse struct {
	Status    string                 `json:"status"`
	TxnID     string                 `json:"txnid,omitempty"`
	Artifacts []ArtifactStatusDetail `json:"artifacts,omitempty"`
	Message   string                 `json:"message,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// ArtifactStatusDetail represents the status of an individual artifact
type ArtifactStatusDetail struct {
	UUID      string `json:"uuid"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	QueuePath string `json:"queue_path,omitempty"`
	Error     string `json:"error,omitempty"`
}

// ArtifactUploader handles uploading artifacts to Vulnetix API
type ArtifactUploader struct {
	baseURL string
	orgID   string
	creds   *auth.Credentials
	client  *http.Client
}

// NewArtifactUploader creates a new artifact uploader using centralized auth
func NewArtifactUploader(baseURL, orgID string) *ArtifactUploader {
	creds, _ := auth.LoadCredentials()

	// If centralized auth didn't find credentials, fall back to legacy env var
	if creds == nil {
		apiKey := os.Getenv("VULNETIX_API_KEY")
		if apiKey != "" {
			creds = &auth.Credentials{
				OrgID:  orgID,
				APIKey: apiKey,
				Method: auth.DirectAPIKey,
			}
		}
	}

	return &ArtifactUploader{
		baseURL: baseURL,
		orgID:   orgID,
		creds:   creds,
		client: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

// validateTxnID validates transaction ID format
func validateTxnID(txnID string) error {
	if txnID == "" {
		return fmt.Errorf("transaction ID cannot be empty")
	}

	// Transaction ID should be alphanumeric with hyphens and underscores
	if !txnIDRegex.MatchString(txnID) {
		return fmt.Errorf("invalid transaction ID format: must contain only alphanumeric characters, hyphens, and underscores")
	}

	return nil
}

// addAuthHeaders adds authentication headers to the request
func (u *ArtifactUploader) addAuthHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "Vulnetix-CLI/1.0")

	if u.creds != nil {
		header := auth.GetAuthHeader(u.creds)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
	}
}

// InitiateTransaction initiates a new artifact upload transaction
func (u *ArtifactUploader) InitiateTransaction(metadata *ArtifactMetadata, artifactNames []string) (*TransactionResponse, error) {
	url := fmt.Sprintf("%s/%s/github/artifact-upload", u.baseURL, u.orgID)

	request := TransactionRequest{
		Meta:      metadata,
		Artifacts: artifactNames,
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	u.addAuthHeaders(req)

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("transaction initiation failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var txnResp TransactionResponse
	if err := json.Unmarshal(respBody, &txnResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !txnResp.Success {
		return nil, fmt.Errorf("transaction initiation failed: %s", txnResp.Message)
	}

	return &txnResp, nil
}

// UploadArtifact uploads a single artifact file to the specified transaction
func (u *ArtifactUploader) UploadArtifact(txnID, artifactName, artifactDir string) (*ArtifactUploadResponse, error) {
	// Validate transaction ID
	if err := validateTxnID(txnID); err != nil {
		return nil, fmt.Errorf("invalid transaction ID: %w", err)
	}

	url := fmt.Sprintf("%s/%s/github/artifact-upload/%s", u.baseURL, u.orgID, txnID)

	// Find all files in the artifact directory
	files, err := findFilesInDir(artifactDir)
	if err != nil {
		return nil, fmt.Errorf("failed to find files in artifact directory: %w", err)
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no files found in artifact directory: %s", artifactDir)
	}

	// Create multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add artifact name as form field
	if err := writer.WriteField("artifact_name", artifactName); err != nil {
		return nil, fmt.Errorf("failed to write artifact name field: %w", err)
	}

	// Add each file to the multipart form
	for _, filePath := range files {
		file, err := os.Open(filePath)
		if err != nil {
			writer.Close()
			return nil, fmt.Errorf("failed to open file %s: %w", filePath, err)
		}

		// Get relative path for the file
		relPath, err := filepath.Rel(artifactDir, filePath)
		if err != nil {
			file.Close()
			writer.Close()
			return nil, fmt.Errorf("failed to get relative path: %w", err)
		}

		part, err := writer.CreateFormFile("files", relPath)
		if err != nil {
			file.Close()
			writer.Close()
			return nil, fmt.Errorf("failed to create form file: %w", err)
		}

		_, err = io.Copy(part, file)
		file.Close()
		if err != nil {
			writer.Close()
			return nil, fmt.Errorf("failed to copy file content: %w", err)
		}
	}

	contentType := writer.FormDataContentType()
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close multipart writer: %w", err)
	}

	// Create and send request
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", contentType)
	u.addAuthHeaders(req)

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upload request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("artifact upload failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var uploadResp ArtifactUploadResponse
	if err := json.Unmarshal(respBody, &uploadResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !uploadResp.Success {
		return nil, fmt.Errorf("artifact upload failed: %s", uploadResp.Message)
	}

	return &uploadResp, nil
}

// GetTransactionStatus retrieves the status of a transaction
func (u *ArtifactUploader) GetTransactionStatus(txnID string) (*StatusResponse, error) {
	// Validate transaction ID
	if err := validateTxnID(txnID); err != nil {
		return nil, fmt.Errorf("invalid transaction ID: %w", err)
	}

	url := fmt.Sprintf("%s/%s/github/artifact-upload/%s/status", u.baseURL, u.orgID, txnID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	u.addAuthHeaders(req)

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("status request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status check failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var statusResp StatusResponse
	if err := json.Unmarshal(respBody, &statusResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &statusResp, nil
}

// GetArtifactStatus retrieves the status of a specific artifact by UUID
func (u *ArtifactUploader) GetArtifactStatus(artifactUUID string) (*StatusResponse, error) {
	if artifactUUID == "" {
		return nil, fmt.Errorf("artifact UUID cannot be empty")
	}

	url := fmt.Sprintf("%s/%s/github/artifact/%s/status", u.baseURL, u.orgID, artifactUUID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	u.addAuthHeaders(req)

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("status request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status check failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var statusResp StatusResponse
	if err := json.Unmarshal(respBody, &statusResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &statusResp, nil
}

// findFilesInDir recursively finds all files in a directory
func findFilesInDir(dir string) ([]string, error) {
	var files []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return files, nil
}
