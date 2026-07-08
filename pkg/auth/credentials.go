package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// credentialsFile is the JSON file name for stored credentials
const credentialsFile = "credentials.json"

// CredentialsDirEnv overrides the default home credential directory
// (~/.vulnetix). Project credentials are unaffected.
const CredentialsDirEnv = "VULNETIX_CREDENTIALS_DIR"

// SourceStatus describes one credential source for status output.
type SourceStatus struct {
	Label  string
	State  string
	Detail string
	Active bool
}

// SaveCredentials persists credentials to the specified store.
//
// When creds.HMACInKeyring is set, the HMAC Secret is written to the OS keychain
// (not the file) and stripped from the on-disk JSON; metadata (org, method,
// token, apikey) is still written to the home/project file. A keychain failure
// is returned so the caller can fall back to file storage.
func SaveCredentials(creds *Credentials, store CredentialStore) error {
	return SaveCredentialsInDir(creds, store, "")
}

// SaveCredentialsInDir persists credentials using baseDir for home/keyring
// metadata when provided.
func SaveCredentialsInDir(creds *Credentials, store CredentialStore, baseDir string) error {
	path, err := storePathInDir(store, baseDir)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Copy so we never mutate the caller's struct while stripping the secret.
	toWrite := *creds
	if store == StoreKeyring {
		if toWrite.Secret != "" {
			toWrite.HMACInKeyring = true
		}
		if toWrite.Token != "" {
			toWrite.TokenInKeyring = true
		}
		if toWrite.APIKey != "" {
			toWrite.APIKeyInKeyring = true
		}
	}
	if toWrite.HMACInKeyring && toWrite.Secret != "" {
		if err := saveSecretToKeyring(hmacKeyringAccount(toWrite.OrgID), toWrite.Secret); err != nil {
			return err
		}
		toWrite.Secret = "" // keep the secret out of the file
	}
	if toWrite.TokenInKeyring && toWrite.Token != "" {
		if err := saveSecretToKeyring(tokenKeyringAccount(toWrite.OrgID), toWrite.Token); err != nil {
			return err
		}
		toWrite.Token = ""
	}
	if toWrite.APIKeyInKeyring && toWrite.APIKey != "" {
		if err := saveSecretToKeyring(apiKeyKeyringAccount(toWrite.OrgID), toWrite.APIKey); err != nil {
			return err
		}
		toWrite.APIKey = ""
	}

	data, err := json.MarshalIndent(&toWrite, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write credentials to %s: %w", path, err)
	}

	return nil
}

// LoadCredentials loads credentials using the following precedence:
//  0. Authentik API token (VULNETIX_API_TOKEN env; org resolved server-side)
//  1. Direct API Key env vars (VULNETIX_API_KEY + VULNETIX_ORG_ID)
//  2. SigV4 env vars (VVD_ORG + VVD_SECRET)
//  3. Project dotfile (.vulnetix/credentials.json)
//  4. Home directory (~/.vulnetix/credentials.json)
//  5. Package Firewall netrc entry (packages.vulnetix.com)
func LoadCredentials() (*Credentials, error) {
	// 0. Authentik API token (current credential; org resolved server-side).
	if tok := os.Getenv("VULNETIX_API_TOKEN"); tok != "" {
		return &Credentials{
			OrgID:  os.Getenv("VULNETIX_ORG_ID"), // optional
			Token:  tok,
			Method: Token,
		}, nil
	}

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

	// 5. Try Package Firewall netrc credentials
	if creds, err := LoadNetrcCredentials(); err == nil {
		return creds, nil
	} else if status := NetrcStatus(); status.Found && status.Err != nil {
		return nil, fmt.Errorf("netrc credentials are not usable: %w", status.Err)
	}

	return nil, fmt.Errorf("no credentials found. Run 'vulnetix auth login' or set VULNETIX_API_KEY + VULNETIX_ORG_ID environment variables")
}

// RemoveCredentials removes stored credentials from all file-based stores and
// clears any HMAC secret held in the OS keychain.
func RemoveCredentials() error {
	var lastErr error
	for _, store := range []CredentialStore{StoreHome, StoreProject} {
		path, err := storePath(store)
		if err != nil {
			continue
		}
		// Clear the keychain secret referenced by this store's metadata first.
		if creds, lerr := loadCredentialMetadata(store); lerr == nil {
			if creds.HMACInKeyring {
				_ = removeSecretFromKeyring(hmacKeyringAccount(creds.OrgID))
			}
			if creds.TokenInKeyring {
				_ = removeSecretFromKeyring(tokenKeyringAccount(creds.OrgID))
			}
			if creds.APIKeyInKeyring {
				_ = removeSecretFromKeyring(apiKeyKeyringAccount(creds.OrgID))
			}
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			lastErr = fmt.Errorf("failed to remove %s: %w", path, err)
		}
	}
	return lastErr
}

// CredentialSource returns the name of the credential source that would win
// in the LoadCredentials precedence chain, or "none" if nothing is configured.
func CredentialSource() string {
	if os.Getenv("VULNETIX_API_TOKEN") != "" {
		return "environment (VULNETIX_API_TOKEN)"
	}
	if os.Getenv("VULNETIX_API_KEY") != "" && os.Getenv("VULNETIX_ORG_ID") != "" {
		return "environment (VULNETIX_API_KEY + VULNETIX_ORG_ID)"
	}
	if os.Getenv("VVD_ORG") != "" && os.Getenv("VVD_SECRET") != "" {
		return "environment (VVD_ORG + VVD_SECRET)"
	}
	if _, err := loadFromFile(StoreProject); err == nil {
		if creds, _ := loadFromFile(StoreProject); creds != nil && creds.usesKeyring() {
			return "keyring (project .vulnetix/credentials.json)"
		}
		return "project (.vulnetix/credentials.json)"
	}
	if _, err := loadFromFile(StoreHome); err == nil {
		if creds, _ := loadFromFile(StoreHome); creds != nil && creds.usesKeyring() {
			return "keyring (home ~/.vulnetix/credentials.json)"
		}
		return "home (~/.vulnetix/credentials.json)"
	}
	if _, err := LoadNetrcCredentials(); err == nil {
		return "netrc (" + PackageFirewallHost + ")"
	}
	return "none"
}

// CredentialStatus returns a human-readable description of the current auth state
func CredentialStatus() (string, *Credentials) {
	creds, err := LoadCredentials()
	if err != nil {
		return "Unauthenticated Community", nil
	}

	source := CredentialSource()
	return fmt.Sprintf("Authenticated via %s (method: %s, org: %s)", source, creds.Method, creds.OrgID), creds
}

// AllSourceStatus returns a compact summary of every credential source and
// whether it is set / found. Useful for diagnostics.
func AllSourceStatus() []string {
	statuses := AllSourceStatusDetailed()
	lines := make([]string, 0, len(statuses)+1)
	for _, status := range statuses {
		line := status.Label + ": " + status.State
		if status.Detail != "" {
			line += " (" + status.Detail + ")"
		}
		lines = append(lines, line)
	}
	lines = append(lines, "Unauthenticated Community (VDB only): available")
	return lines
}

// AllSourceStatusDetailed returns structured credential-source status.
func AllSourceStatusDetailed() []SourceStatus {
	active := CredentialSource()
	statuses := []SourceStatus{
		{
			Label:  "env VULNETIX_API_TOKEN",
			State:  stateFromBool(os.Getenv("VULNETIX_API_TOKEN") != ""),
			Active: active == "environment (VULNETIX_API_TOKEN)",
		},
		{
			Label:  "env VULNETIX_API_KEY + VULNETIX_ORG_ID",
			State:  stateFromBool(os.Getenv("VULNETIX_API_KEY") != "" && os.Getenv("VULNETIX_ORG_ID") != ""),
			Active: active == "environment (VULNETIX_API_KEY + VULNETIX_ORG_ID)",
		},
		{
			Label:  "env VVD_ORG + VVD_SECRET",
			State:  stateFromBool(os.Getenv("VVD_ORG") != "" && os.Getenv("VVD_SECRET") != ""),
			Active: active == "environment (VVD_ORG + VVD_SECRET)",
		},
	}

	project, projectErr := fileSourceStatus(StoreProject, "project .vulnetix/credentials.json", "project (.vulnetix/credentials.json)", active)
	statuses = append(statuses, project)

	homeLabel := "home ~/.vulnetix/credentials.json"
	if dir := credentialsBaseDir(""); dir != "" {
		homeLabel = "home " + filepath.Join(dir, credentialsFile)
	}
	home, homeErr := fileSourceStatus(StoreHome, homeLabel, "home (~/.vulnetix/credentials.json)", active)
	statuses = append(statuses, home)

	keyring := SourceStatus{Label: "keyring", State: "not set"}
	for _, item := range []struct {
		store CredentialStore
		err   error
	}{
		{StoreProject, projectErr},
		{StoreHome, homeErr},
	} {
		meta, err := loadCredentialMetadata(item.store)
		if err != nil || !meta.usesKeyring() {
			continue
		}
		keyring.State = "set"
		keyring.Detail = "referenced by " + string(item.store) + " credentials"
		keyring.Active = activeHasPrefix(active, "keyring")
		if item.err != nil {
			keyring.State = "unusable"
			keyring.Detail = item.err.Error()
		}
		break
	}
	statuses = append(statuses, keyring)

	netrc := NetrcStatus()
	netrcStatus := SourceStatus{Label: "netrc " + netrc.Path + " machine " + PackageFirewallHost, Active: active == "netrc ("+PackageFirewallHost+")"}
	switch {
	case !netrc.Found:
		netrcStatus.State = "not set"
	case netrc.Err != nil:
		netrcStatus.State = "unusable"
		netrcStatus.Detail = netrc.Err.Error()
	case netrc.MachineFound:
		netrcStatus.State = "set"
	default:
		netrcStatus.State = "not set"
	}
	statuses = append(statuses, netrcStatus)

	return statuses
}

func stateFromBool(ok bool) string {
	if ok {
		return "set"
	}
	return "not set"
}

func activeHasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func fileSourceStatus(store CredentialStore, label, activeSource string, active string) (SourceStatus, error) {
	status := SourceStatus{Label: label, State: "not set", Active: active == activeSource}
	if _, err := storePath(store); err != nil {
		status.State = "unusable"
		status.Detail = err.Error()
		return status, err
	}
	_, err := loadFromFile(store)
	if err == nil {
		status.State = "set"
		return status, nil
	}
	if os.IsNotExist(err) {
		return status, err
	}
	status.State = "unusable"
	status.Detail = err.Error()
	return status, err
}

func loadFromFile(store CredentialStore) (*Credentials, error) {
	creds, path, err := readCredentialsFile(store)
	if err != nil {
		return nil, err
	}

	// Hydrate secrets from the OS keychain when metadata says they live there.
	if creds.HMACInKeyring && creds.Secret == "" {
		secret, kerr := loadRequiredSecretFromKeyring(hmacKeyringAccount(creds.OrgID))
		if kerr != nil {
			return nil, fmt.Errorf("credentials file %s references an unusable keyring secret: %w", path, kerr)
		}
		creds.Secret = secret
	}
	if creds.TokenInKeyring && creds.Token == "" {
		token, kerr := loadRequiredSecretFromKeyring(tokenKeyringAccount(creds.OrgID))
		if kerr != nil {
			return nil, fmt.Errorf("credentials file %s references an unusable keyring token: %w", path, kerr)
		}
		creds.Token = token
	}
	if creds.APIKeyInKeyring && creds.APIKey == "" {
		apiKey, kerr := loadRequiredSecretFromKeyring(apiKeyKeyringAccount(creds.OrgID))
		if kerr != nil {
			return nil, fmt.Errorf("credentials file %s references an unusable keyring API key: %w", path, kerr)
		}
		creds.APIKey = apiKey
	}

	if creds.OrgID == "" && creds.Token == "" {
		return nil, fmt.Errorf("credentials file %s is missing org_id", path)
	}

	return creds, nil
}

func storePath(store CredentialStore) (string, error) {
	return storePathInDir(store, "")
}

func storePathInDir(store CredentialStore, baseDir string) (string, error) {
	switch store {
	case StoreHome:
		return filepath.Join(credentialsBaseDir(baseDir), credentialsFile), nil
	case StoreProject:
		return filepath.Join(".vulnetix", credentialsFile), nil
	case StoreKeyring:
		// Keyring stores the secret in the OS keychain but keeps credential
		// metadata (org, method, token) in the home-directory file.
		return filepath.Join(credentialsBaseDir(baseDir), credentialsFile), nil
	default:
		return "", fmt.Errorf("unknown store: %s", store)
	}
}

func credentialsBaseDir(baseDir string) string {
	if baseDir != "" {
		return baseDir
	}
	if envDir := os.Getenv(CredentialsDirEnv); envDir != "" {
		return envDir
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ".vulnetix"
	}
	return filepath.Join(homeDir, ".vulnetix")
}

func loadCredentialMetadata(store CredentialStore) (*Credentials, error) {
	creds, _, err := readCredentialsFile(store)
	return creds, err
}

func readCredentialsFile(store CredentialStore) (*Credentials, string, error) {
	path, err := storePath(store)
	if err != nil {
		return nil, "", err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, path, err
	}

	var creds Credentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, path, fmt.Errorf("failed to parse credentials from %s: %w", path, err)
	}
	return &creds, path, nil
}

func (c *Credentials) usesKeyring() bool {
	return c != nil && (c.HMACInKeyring || c.TokenInKeyring || c.APIKeyInKeyring)
}
