package github

import (
	"testing"
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
