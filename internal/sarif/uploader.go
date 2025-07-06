package sarif

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"
)

// UploadConfig contains configuration for SARIF upload
type UploadConfig struct {
	BaseURL     string
	OrgID       string
	Timeout     time.Duration
	ContentType string
}

// UploadResponse represents the response from SARIF upload
type UploadResponse struct {
	UUID       string `json:"uuid"`
	Success    bool   `json:"success"`
	Message    string `json:"message,omitempty"`
	StatusCode int    `json:"statusCode"`
}

// Uploader handles SARIF file uploads
type Uploader struct {
	config *UploadConfig
	client *http.Client
}

// NewUploader creates a new SARIF uploader
func NewUploader(config *UploadConfig) *Uploader {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	client := &http.Client{
		Timeout: config.Timeout,
	}

	return &Uploader{
		config: config,
		client: client,
	}
}

// Upload uploads SARIF data to the configured endpoint
func (u *Uploader) Upload(sarifData []byte) (*UploadResponse, error) {
	// Validate SARIF before upload
	validator := NewValidator()
	validation, err := validator.ValidateFromBytes(sarifData)
	if err != nil {
		return nil, fmt.Errorf("validation error: %w", err)
	}

	if !validation.Valid {
		return &UploadResponse{
			Success:    false,
			Message:    fmt.Sprintf("SARIF validation failed: %v", validation.Errors),
			StatusCode: 400,
		}, nil
	}

	// Prepare the upload request
	url := fmt.Sprintf("%s/api/sarif/upload", u.config.BaseURL)
	
	req, err := http.NewRequest("POST", url, bytes.NewReader(sarifData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("X-Org-ID", u.config.OrgID)
	req.Header.Set("Content-Type", u.config.ContentType)
	req.Header.Set("User-Agent", "Vulnetix-CLI/1.0")

	// Perform the request
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upload request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Handle different status codes
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		// Extract UUID from response body (assuming it's returned as plain text or JSON)
		return &UploadResponse{
			UUID:       string(respBody),
			Success:    true,
			StatusCode: resp.StatusCode,
		}, nil
	case http.StatusBadRequest:
		return &UploadResponse{
			Success:    false,
			Message:    fmt.Sprintf("Bad request: %s", string(respBody)),
			StatusCode: resp.StatusCode,
		}, nil
	case http.StatusUnauthorized:
		return &UploadResponse{
			Success:    false,
			Message:    "Invalid or missing organization ID",
			StatusCode: resp.StatusCode,
		}, nil
	case http.StatusForbidden:
		return &UploadResponse{
			Success:    false,
			Message:    "Organization access forbidden",
			StatusCode: resp.StatusCode,
		}, nil
	case http.StatusNotFound:
		return &UploadResponse{
			Success:    false,
			Message:    "Organization not found",
			StatusCode: resp.StatusCode,
		}, nil
	case http.StatusRequestEntityTooLarge:
		return &UploadResponse{
			Success:    false,
			Message:    "SARIF file too large",
			StatusCode: resp.StatusCode,
		}, nil
	case http.StatusInternalServerError:
		return &UploadResponse{
			Success:    false,
			Message:    "Server error during upload",
			StatusCode: resp.StatusCode,
		}, nil
	default:
		return &UploadResponse{
			Success:    false,
			Message:    fmt.Sprintf("Unexpected status code %d: %s", resp.StatusCode, string(respBody)),
			StatusCode: resp.StatusCode,
		}, nil
	}
}

// DetermineContentType determines the appropriate content type based on input method
func DetermineContentType(inputMethod string) string {
	switch inputMethod {
	case "stdin":
		return "application/json"
	case "pipe":
		return "application/json"
	case "file":
		return "application/json"
	case "string":
		return "application/json"
	default:
		return "application/json"
	}
}