package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// credentialsFile is the JSON file name for stored credentials
const credentialsFile = "credentials.json"

// SaveCredentials persists credentials to the specified store
func SaveCredentials(creds *Credentials, store CredentialStore) error {
	path, err := storePath(store)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write credentials to %s: %w", path, err)
	}

	return nil
}

// LoadCredentials loads credentials using the following precedence:
//  1. Environment variables (VULNETIX_API_KEY + VULNETIX_ORG_ID for Direct, VVD_ORG + VVD_SECRET for SigV4)
//  2. Project dotfile (.vulnetix/credentials.json)
//  3. Home directory (~/.vulnetix/credentials.json)
func LoadCredentials() (*Credentials, error) {
	// 1. Try Direct API Key env vars
	apiKey := os.Getenv("VULNETIX_API_KEY")
	orgID := os.Getenv("VULNETIX_ORG_ID")
	if apiKey != "" && orgID != "" {
		return &Credentials{
			OrgID:  orgID,
			APIKey: apiKey,
			Method: DirectAPIKey,
		}, nil
	}

	// 2. Try SigV4 env vars
	vvdOrg := os.Getenv("VVD_ORG")
	vvdSecret := os.Getenv("VVD_SECRET")
	if vvdOrg != "" && vvdSecret != "" {
		return &Credentials{
			OrgID:  vvdOrg,
			Secret: vvdSecret,
			Method: SigV4,
		}, nil
	}

	// 3. Try project dotfile
	if creds, err := loadFromFile(StoreProject); err == nil {
		return creds, nil
	}

	// 4. Try home directory
	if creds, err := loadFromFile(StoreHome); err == nil {
		return creds, nil
	}

	return nil, fmt.Errorf("no credentials found. Run 'vulnetix auth login' or set VULNETIX_API_KEY + VULNETIX_ORG_ID environment variables")
}

// RemoveCredentials removes stored credentials from all file-based stores
func RemoveCredentials() error {
	var lastErr error
	for _, store := range []CredentialStore{StoreHome, StoreProject} {
		path, err := storePath(store)
		if err != nil {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			lastErr = fmt.Errorf("failed to remove %s: %w", path, err)
		}
	}
	return lastErr
}

// CredentialStatus returns a human-readable description of the current auth state
func CredentialStatus() (string, *Credentials) {
	creds, err := LoadCredentials()
	if err != nil {
		return "Not authenticated", nil
	}

	source := "unknown"

	// Determine source
	apiKey := os.Getenv("VULNETIX_API_KEY")
	orgID := os.Getenv("VULNETIX_ORG_ID")
	if apiKey != "" && orgID != "" {
		source = "environment (VULNETIX_API_KEY + VULNETIX_ORG_ID)"
	} else if os.Getenv("VVD_ORG") != "" && os.Getenv("VVD_SECRET") != "" {
		source = "environment (VVD_ORG + VVD_SECRET)"
	} else if _, err := loadFromFile(StoreProject); err == nil {
		source = "project (.vulnetix/credentials.json)"
	} else if _, err := loadFromFile(StoreHome); err == nil {
		source = "home (~/.vulnetix/credentials.json)"
	}

	return fmt.Sprintf("Authenticated via %s (method: %s, org: %s)", source, creds.Method, creds.OrgID), creds
}

func loadFromFile(store CredentialStore) (*Credentials, error) {
	path, err := storePath(store)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var creds Credentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("failed to parse credentials from %s: %w", path, err)
	}

	if creds.OrgID == "" {
		return nil, fmt.Errorf("credentials file %s is missing org_id", path)
	}

	return &creds, nil
}

func storePath(store CredentialStore) (string, error) {
	switch store {
	case StoreHome:
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to determine home directory: %w", err)
		}
		return filepath.Join(homeDir, ".vulnetix", credentialsFile), nil
	case StoreProject:
		return filepath.Join(".vulnetix", credentialsFile), nil
	case StoreKeyring:
		return "", fmt.Errorf("keyring storage is not yet implemented")
	default:
		return "", fmt.Errorf("unknown store: %s", store)
	}
}
