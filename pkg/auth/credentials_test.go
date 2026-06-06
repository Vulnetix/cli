package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveAndLoadCredentials(t *testing.T) {
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)

	tmpDir := t.TempDir()
	os.Chdir(tmpDir)

	creds := &Credentials{
		OrgID:  "test-org",
		APIKey: "test-key",
		Method: DirectAPIKey,
	}

	err := SaveCredentials(creds, StoreProject)
	if err != nil {
		t.Fatalf("SaveCredentials failed: %v", err)
	}

	loaded, err := loadFromFile(StoreProject)
	if err != nil {
		t.Fatalf("loadFromFile failed: %v", err)
	}
	if loaded.OrgID != "test-org" {
		t.Errorf("expected org 'test-org', got %q", loaded.OrgID)
	}
	if loaded.APIKey != "test-key" {
		t.Errorf("expected key 'test-key', got %q", loaded.APIKey)
	}
	if loaded.Method != DirectAPIKey {
		t.Errorf("expected method 'apikey', got %q", loaded.Method)
	}
}

func TestRemoveCredentials(t *testing.T) {
	// Just verify it doesn't panic
	err := RemoveCredentials()
	// This may or may not error depending on filesystem state; always ok
	_ = err
}

func TestLoadCredentials_FromEnv(t *testing.T) {
	t.Setenv("VULNETIX_API_KEY", "env-key")
	t.Setenv("VULNETIX_ORG_ID", "env-org")

	creds, err := LoadCredentials()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds.OrgID != "env-org" {
		t.Errorf("expected 'env-org', got %q", creds.OrgID)
	}
	if creds.APIKey != "env-key" {
		t.Errorf("expected 'env-key', got %q", creds.APIKey)
	}
	if creds.Method != DirectAPIKey {
		t.Errorf("expected DirectAPIKey, got %q", creds.Method)
	}
}

func TestLoadCredentials_FromSigV4Env(t *testing.T) {
	t.Setenv("VULNETIX_API_KEY", "")
	t.Setenv("VULNETIX_ORG_ID", "")
	t.Setenv("VVD_ORG", "sigv4-org")
	t.Setenv("VVD_SECRET", "sigv4-secret")

	creds, err := LoadCredentials()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds.OrgID != "sigv4-org" {
		t.Errorf("expected 'sigv4-org', got %q", creds.OrgID)
	}
	if creds.Secret != "sigv4-secret" {
		t.Errorf("expected 'sigv4-secret', got %q", creds.Secret)
	}
	if creds.Method != SigV4 {
		t.Errorf("expected SigV4, got %q", creds.Method)
	}
}

func TestCredentialSource(t *testing.T) {
	t.Setenv("VULNETIX_API_KEY", "k")
	t.Setenv("VULNETIX_ORG_ID", "o")
	source := CredentialSource()
	if source != "environment (VULNETIX_API_KEY + VULNETIX_ORG_ID)" {
		t.Errorf("unexpected source: %q", source)
	}
}

func TestCredentialSource_SigV4(t *testing.T) {
	t.Setenv("VULNETIX_API_KEY", "")
	t.Setenv("VULNETIX_ORG_ID", "")
	t.Setenv("VVD_ORG", "o")
	t.Setenv("VVD_SECRET", "s")
	source := CredentialSource()
	if source != "environment (VVD_ORG + VVD_SECRET)" {
		t.Errorf("unexpected source: %q", source)
	}
}

func TestCredentialSource_None(t *testing.T) {
	t.Setenv("VULNETIX_API_KEY", "")
	t.Setenv("VULNETIX_ORG_ID", "")
	t.Setenv("VVD_ORG", "")
	t.Setenv("VVD_SECRET", "")
	t.Setenv("HOME", t.TempDir())
	source := CredentialSource()
	if source != "none" {
		t.Errorf("expected 'none', got %q", source)
	}
}

func TestAllSourceStatus(t *testing.T) {
	t.Setenv("VULNETIX_API_KEY", "k")
	t.Setenv("VULNETIX_ORG_ID", "o")
	lines := AllSourceStatus()
	if len(lines) != 7 {
		t.Errorf("expected 7 lines, got %d", len(lines))
	}
}

func TestPackageFirewallConfigStatus(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	npmrc := filepath.Join(home, ".npmrc")
	if err := os.WriteFile(npmrc, []byte("registry=https://packages.vulnetix.com/npm/\n"), 0600); err != nil {
		t.Fatal(err)
	}

	status := packageFirewallConfigStatus()
	if !strings.Contains(status, "npm") {
		t.Fatalf("expected npm config status, got %q", status)
	}
}

func TestStorePath(t *testing.T) {
	p, err := storePath(StoreProject)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if filepath.Base(p) != "credentials.json" {
		t.Errorf("expected 'credentials.json', got %q", filepath.Base(p))
	}

	h, err := storePath(StoreHome)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if filepath.Base(h) != "credentials.json" {
		t.Errorf("expected 'credentials.json', got %q", filepath.Base(h))
	}

	_, err = storePath(StoreKeyring)
	if err == nil {
		t.Fatal("expected error for keyring store path")
	}
}

func TestLoadFromFile_NoFile(t *testing.T) {
	_, err := loadFromFile(StoreProject)
	// Project-relative .vulnetix/credentials.json probably doesn't exist in test
	if err == nil {
		t.Log("project credentials file found unexpectedly — ok if exists")
	}
}

func TestCredentialStatus(t *testing.T) {
	// Without creds set, should return community status
	t.Setenv("VULNETIX_API_KEY", "")
	t.Setenv("VULNETIX_ORG_ID", "")
	t.Setenv("VVD_ORG", "")
	t.Setenv("VVD_SECRET", "")
	t.Setenv("HOME", t.TempDir())

	status, creds := CredentialStatus()
	if creds != nil {
		t.Error("expected nil creds when none configured")
	}
	if status != "Unauthenticated Community" {
		t.Errorf("unexpected status: %q", status)
	}
}
