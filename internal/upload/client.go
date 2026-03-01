package upload

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vulnetix/vulnetix/internal/auth"
)

const (
	DefaultBaseURL = "https://app.vulnetix.com/api"
	// ChunkThreshold is the file size above which chunked upload is used
	ChunkThreshold = 10 * 1024 * 1024 // 10 MB
	// DefaultChunkSize is the size of each chunk for large files
	DefaultChunkSize = 5 * 1024 * 1024 // 5 MB
)

// Client handles file uploads to the Vulnetix API
type Client struct {
	BaseURL    string
	Creds      *auth.Credentials
	HTTPClient *http.Client
}

// InitiateResponse is returned when starting an upload session
type InitiateResponse struct {
	OK              bool   `json:"ok"`
	UploadSessionID string `json:"uploadSessionId"`
	ExpiresAt       int64  `json:"expiresAt,omitempty"`
	Error           string `json:"error,omitempty"`
}

// ChunkResponse is returned after uploading a chunk
type ChunkResponse struct {
	OK          bool   `json:"ok"`
	ChunkNumber int    `json:"chunkNumber"`
	Received    int    `json:"received"`
	TotalChunks int    `json:"totalChunks"`
	Error       string `json:"error,omitempty"`
}

// PipelineRecord represents the artifact pipeline record from the SaaS
type PipelineRecord struct {
	UUID                string `json:"uuid"`
	DetectedType        string `json:"detectedType"`
	ProcessingState     string `json:"processingState"`
	OriginalFileName    string `json:"originalFileName"`
	SHA256              string `json:"sha256,omitempty"`
}

// FinalizeResponse is returned after finalizing an upload
type FinalizeResponse struct {
	OK             bool            `json:"ok"`
	PipelineRecord *PipelineRecord `json:"pipelineRecord,omitempty"`
	IsDuplicate    bool            `json:"isDuplicate,omitempty"`
	Error          string          `json:"error,omitempty"`
}

// NewClient creates a new upload client
func NewClient(baseURL string, creds *auth.Credentials) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{
		BaseURL: baseURL,
		Creds:   creds,
		HTTPClient: &http.Client{
			Timeout: 300 * time.Second,
		},
	}
}

// UploadFile uploads a file to Vulnetix, choosing simple or chunked based on size
func (c *Client) UploadFile(filePath string, formatOverride string) (*FinalizeResponse, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	fileName := filepath.Base(filePath)
	contentType := "application/octet-stream"
	format := formatOverride
	if format == "" {
		format = DetectFormat(filePath, data)
	}

	if strings.HasSuffix(fileName, ".json") {
		contentType = "application/json"
	} else if strings.HasSuffix(fileName, ".xml") {
		contentType = "application/xml"
	}

	if len(data) < ChunkThreshold {
		return c.SimpleUpload(fileName, data, contentType, format)
	}
	return c.ChunkedUpload(fileName, data, contentType, format)
}

// SimpleUpload performs a single-request upload for small files
func (c *Client) SimpleUpload(fileName string, data []byte, contentType, format string) (*FinalizeResponse, error) {
	// Initiate
	session, err := c.InitiateSession(fileName, len(data), contentType, 1, len(data))
	if err != nil {
		return nil, fmt.Errorf("failed to initiate upload: %w", err)
	}

	// Single chunk
	if _, err := c.UploadChunk(session.UploadSessionID, 1, data); err != nil {
		return nil, fmt.Errorf("failed to upload data: %w", err)
	}

	// Finalize
	result, err := c.FinalizeUpload(session.UploadSessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to finalize upload: %w", err)
	}

	return result, nil
}

// InitiateSession starts a new upload session
func (c *Client) InitiateSession(fileName string, fileSize int, contentType string, totalChunks, chunkSize int) (*InitiateResponse, error) {
	body := map[string]interface{}{
		"fileName":    fileName,
		"fileSize":    fileSize,
		"contentType": contentType,
		"totalChunks": totalChunks,
		"chunkSize":   chunkSize,
	}

	respBody, err := c.doRequest("POST", "/artifact-upload/initiate", body)
	if err != nil {
		return nil, err
	}

	var resp InitiateResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse initiate response: %w", err)
	}

	if !resp.OK {
		return nil, fmt.Errorf("initiate failed: %s", resp.Error)
	}

	return &resp, nil
}

// UploadChunk uploads a single chunk of data
func (c *Client) UploadChunk(sessionID string, chunkNumber int, data []byte) (*ChunkResponse, error) {
	path := fmt.Sprintf("/artifact-upload/chunk/%s/%d", sessionID, chunkNumber)

	req, err := http.NewRequest("POST", c.BaseURL+path, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	c.addAuth(req)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("chunk upload failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("chunk upload failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var chunkResp ChunkResponse
	if err := json.Unmarshal(respBody, &chunkResp); err != nil {
		return nil, fmt.Errorf("failed to parse chunk response: %w", err)
	}

	return &chunkResp, nil
}

// FinalizeUpload completes the upload session
func (c *Client) FinalizeUpload(sessionID string) (*FinalizeResponse, error) {
	path := fmt.Sprintf("/artifact-upload/finalize/%s", sessionID)

	// Finalize accepts an optional body with collectionUuid
	respBody, err := c.doRequest("POST", path, map[string]interface{}{})
	if err != nil {
		return nil, err
	}

	var resp FinalizeResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse finalize response: %w", err)
	}

	if !resp.OK {
		return nil, fmt.Errorf("finalize failed: %s", resp.Error)
	}

	return &resp, nil
}

// VerifyResponse is returned by the /api/cli/verify endpoint
type VerifyResponse struct {
	OK    bool   `json:"ok"`
	OrgID string `json:"orgId,omitempty"`
	Error string `json:"error,omitempty"`
}

// VerifyAuth checks that the provided credentials are valid
func (c *Client) VerifyAuth() (*VerifyResponse, error) {
	respBody, err := c.doRequest("GET", "/cli/verify", nil)
	if err != nil {
		return nil, err
	}

	var resp VerifyResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse verify response: %w", err)
	}

	if !resp.OK {
		return nil, fmt.Errorf("auth verification failed: %s", resp.Error)
	}

	return &resp, nil
}

func (c *Client) doRequest(method, path string, body interface{}) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.BaseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c.addAuth(req)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

func (c *Client) addAuth(req *http.Request) {
	req.Header.Set("User-Agent", "Vulnetix-CLI/1.0")
	if c.Creds != nil {
		header := auth.GetAuthHeader(c.Creds)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
	}
}

// DetectFormat inspects file extension and content to determine the artifact format
func DetectFormat(filePath string, data []byte) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	name := strings.ToLower(filepath.Base(filePath))

	// Check file name patterns
	if strings.Contains(name, ".cdx.") || strings.Contains(name, "cyclonedx") {
		return "cyclonedx"
	}
	if strings.Contains(name, ".spdx.") || strings.Contains(name, "spdx") {
		return "spdx"
	}
	if strings.Contains(name, ".sarif") || strings.HasSuffix(name, ".sarif.json") {
		return "sarif"
	}
	if strings.Contains(name, ".vex.") || strings.Contains(name, "openvex") {
		return "openvex"
	}
	if strings.Contains(name, ".csaf.") || strings.Contains(name, "csaf") {
		return "csaf_vex"
	}

	// Check content for JSON files
	if ext == ".json" && len(data) > 0 {
		content := string(data[:min(len(data), 2048)])

		if strings.Contains(content, "\"bomFormat\"") || strings.Contains(content, "\"specVersion\"") {
			return "cyclonedx"
		}
		if strings.Contains(content, "\"spdxVersion\"") {
			return "spdx"
		}
		if strings.Contains(content, "\"$schema\"") && strings.Contains(content, "sarif") {
			return "sarif"
		}
		if strings.Contains(content, "\"@context\"") && strings.Contains(content, "openvex") {
			return "openvex"
		}
	}

	return "auto"
}
