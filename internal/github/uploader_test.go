package github

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulnetix/cli/internal/auth"
)

func TestNewArtifactUploader(t *testing.T) {
	baseURL := "https://api.vulnetix.com"
	orgID := "123e4567-e89b-12d3-a456-426614174000"

	uploader := NewArtifactUploader(baseURL, orgID)

	if uploader.baseURL != baseURL {
		t.Errorf("Expected baseURL '%s', got '%s'", baseURL, uploader.baseURL)
	}

	if uploader.orgID != orgID {
		t.Errorf("Expected orgID '%s', got '%s'", orgID, uploader.orgID)
	}

	if uploader.client == nil {
		t.Error("Expected client to be initialized")
	}

	if uploader.client.Timeout == 0 {
		t.Error("Expected client timeout to be set")
	}
}

func TestTransactionRequest(t *testing.T) {
	metadata := &ArtifactMetadata{
		Repository:      "test/repo",
		RepositoryOwner: "test",
		RunID:           "123456",
		Artifacts:       []string{"artifact1", "artifact2"},
	}

	artifactNames := []string{"artifact1", "artifact2"}

	req := TransactionRequest{
		Meta:      metadata,
		Artifacts: artifactNames,
	}

	if req.Meta.Repository != "test/repo" {
		t.Errorf("Expected repository 'test/repo', got '%s'", req.Meta.Repository)
	}

	if len(req.Artifacts) != 2 {
		t.Errorf("Expected 2 artifacts, got %d", len(req.Artifacts))
	}
}

func TestArtifactStatusDetail(t *testing.T) {
	status := ArtifactStatusDetail{
		UUID:      "test-uuid",
		Name:      "test-artifact",
		Status:    "completed",
		QueuePath: "/queue/path",
	}

	if status.UUID != "test-uuid" {
		t.Errorf("Expected UUID 'test-uuid', got '%s'", status.UUID)
	}

	if status.Name != "test-artifact" {
		t.Errorf("Expected name 'test-artifact', got '%s'", status.Name)
	}

	if status.Status != "completed" {
		t.Errorf("Expected status 'completed', got '%s'", status.Status)
	}

	if status.QueuePath != "/queue/path" {
		t.Errorf("Expected queue path '/queue/path', got '%s'", status.QueuePath)
	}
}

func TestValidateTxnID(t *testing.T) {
	tests := []struct {
		name      string
		txnID     string
		expectErr bool
	}{
		{"valid alphanumeric", "abc123", false},
		{"valid with hyphens", "abc-123-def", false},
		{"valid with underscores", "abc_123_def", false},
		{"empty string", "", true},
		{"with special chars", "abc@123", true},
		{"with spaces", "abc 123", true},
		{"with path separator", "abc/123", true},
		{"with dots", "abc.123", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTxnID(tt.txnID)
			if tt.expectErr && err == nil {
				t.Errorf("Expected error for txnID '%s', got nil", tt.txnID)
			}
			if !tt.expectErr && err != nil {
				t.Errorf("Expected no error for txnID '%s', got: %v", tt.txnID, err)
			}
		})
	}
}

func TestNewArtifactUploader_WithAPIKey(t *testing.T) {
	// Set API key environment variable
	t.Setenv("VULNETIX_API_KEY", "test-api-key")
	t.Setenv("VULNETIX_ORG_ID", "test-org-id")

	uploader := NewArtifactUploader("https://api.vulnetix.com", "test-org-id")

	if uploader.creds == nil {
		t.Fatal("Expected credentials to be loaded")
	}
	if uploader.creds.APIKey != "test-api-key" {
		t.Errorf("Expected API key 'test-api-key', got '%s'", uploader.creds.APIKey)
	}
}

func TestInitiateTransaction(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}

		// Verify content type
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		// Read and verify request body
		body, _ := io.ReadAll(r.Body)
		var req TransactionRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("Failed to unmarshal request: %v", err)
		}

		// Return mock response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		resp := TransactionResponse{
			TxnID:   "test-txn-123",
			Success: true,
			Message: "Transaction initiated",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	uploader := &ArtifactUploader{
		baseURL: server.URL,
		orgID:   "test-org",
		client:  &http.Client{},
	}

	metadata := &ArtifactMetadata{
		Repository: "test/repo",
		RunID:      "123",
		Artifacts:  []string{"artifact1"},
	}

	txnResp, err := uploader.InitiateTransaction(metadata, []string{"artifact1"})
	if err != nil {
		t.Fatalf("InitiateTransaction failed: %v", err)
	}

	if txnResp.TxnID != "test-txn-123" {
		t.Errorf("Expected TxnID 'test-txn-123', got '%s'", txnResp.TxnID)
	}

	if !txnResp.Success {
		t.Error("Expected Success to be true")
	}
}

func TestInitiateTransaction_WithAuth(t *testing.T) {
	apiKey := "test-api-key"
	testOrgID := "test-org"

	// Create a test server that checks auth
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify auth header uses ApiKey format
		expectedAuth := "ApiKey " + testOrgID + ":" + apiKey
		if r.Header.Get("Authorization") != expectedAuth {
			t.Errorf("Expected Authorization header '%s', got '%s'", expectedAuth, r.Header.Get("Authorization"))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		resp := TransactionResponse{
			TxnID:   "test-txn-123",
			Success: true,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	uploader := &ArtifactUploader{
		baseURL: server.URL,
		orgID:   testOrgID,
		creds: &auth.Credentials{
			OrgID:  testOrgID,
			APIKey: apiKey,
			Method: auth.DirectAPIKey,
		},
		client: &http.Client{},
	}

	metadata := &ArtifactMetadata{
		Repository: "test/repo",
		RunID:      "123",
	}

	_, err := uploader.InitiateTransaction(metadata, []string{"artifact1"})
	if err != nil {
		t.Fatalf("InitiateTransaction failed: %v", err)
	}
}

func TestUploadArtifact(t *testing.T) {
	// Create temporary artifact directory with test files
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}

		// Verify content type is multipart
		contentType := r.Header.Get("Content-Type")
		if !strings.HasPrefix(contentType, "multipart/form-data") {
			t.Errorf("Expected multipart/form-data content type, got %s", contentType)
		}

		// Return mock response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		resp := ArtifactUploadResponse{
			UUID:      "artifact-uuid-123",
			QueuePath: "/queue/path",
			Success:   true,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	uploader := &ArtifactUploader{
		baseURL: server.URL,
		orgID:   "test-org",
		client:  &http.Client{},
	}

	uploadResp, err := uploader.UploadArtifact("test-txn-123", "test-artifact", tmpDir)
	if err != nil {
		t.Fatalf("UploadArtifact failed: %v", err)
	}

	if uploadResp.UUID != "artifact-uuid-123" {
		t.Errorf("Expected UUID 'artifact-uuid-123', got '%s'", uploadResp.UUID)
	}

	if !uploadResp.Success {
		t.Error("Expected Success to be true")
	}
}

func TestUploadArtifact_InvalidTxnID(t *testing.T) {
	tmpDir := t.TempDir()
	
	uploader := &ArtifactUploader{
		baseURL: "https://api.vulnetix.com",
		orgID:   "test-org",
		client:  &http.Client{},
	}

	_, err := uploader.UploadArtifact("invalid/txnid", "test-artifact", tmpDir)
	if err == nil {
		t.Error("Expected error for invalid transaction ID, got nil")
	}

	if !strings.Contains(err.Error(), "invalid transaction ID") {
		t.Errorf("Expected invalid transaction ID error, got: %v", err)
	}
}

func TestGetTransactionStatus(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method
		if r.Method != "GET" {
			t.Errorf("Expected GET request, got %s", r.Method)
		}

		// Verify URL path
		expectedPath := "/test-org/github/artifact-upload/test-txn-123/status"
		if r.URL.Path != expectedPath {
			t.Errorf("Expected path %s, got %s", expectedPath, r.URL.Path)
		}

		// Return mock response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := StatusResponse{
			Status: "completed",
			TxnID:  "test-txn-123",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	uploader := &ArtifactUploader{
		baseURL: server.URL,
		orgID:   "test-org",
		client:  &http.Client{},
	}

	statusResp, err := uploader.GetTransactionStatus("test-txn-123")
	if err != nil {
		t.Fatalf("GetTransactionStatus failed: %v", err)
	}

	if statusResp.Status != "completed" {
		t.Errorf("Expected status 'completed', got '%s'", statusResp.Status)
	}

	if statusResp.TxnID != "test-txn-123" {
		t.Errorf("Expected TxnID 'test-txn-123', got '%s'", statusResp.TxnID)
	}
}

func TestGetArtifactStatus(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method
		if r.Method != "GET" {
			t.Errorf("Expected GET request, got %s", r.Method)
		}

		// Return mock response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := StatusResponse{
			Status: "processing",
			Artifacts: []ArtifactStatusDetail{
				{
					UUID:   "artifact-uuid-123",
					Name:   "test-artifact",
					Status: "processing",
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	uploader := &ArtifactUploader{
		baseURL: server.URL,
		orgID:   "test-org",
		client:  &http.Client{},
	}

	statusResp, err := uploader.GetArtifactStatus("artifact-uuid-123")
	if err != nil {
		t.Fatalf("GetArtifactStatus failed: %v", err)
	}

	if statusResp.Status != "processing" {
		t.Errorf("Expected status 'processing', got '%s'", statusResp.Status)
	}

	if len(statusResp.Artifacts) != 1 {
		t.Errorf("Expected 1 artifact, got %d", len(statusResp.Artifacts))
	}
}

func TestGetArtifactStatus_EmptyUUID(t *testing.T) {
	uploader := &ArtifactUploader{
		baseURL: "https://api.vulnetix.com",
		orgID:   "test-org",
		client:  &http.Client{},
	}

	_, err := uploader.GetArtifactStatus("")
	if err == nil {
		t.Error("Expected error for empty UUID, got nil")
	}

	if !strings.Contains(err.Error(), "UUID cannot be empty") {
		t.Errorf("Expected empty UUID error, got: %v", err)
	}
}
