package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	pfw "github.com/vulnetix/cli/v3/pkg/packagefirewall"
)

// credentialsFile is the JSON file name for stored credentials
const credentialsFile = "credentials.json"

// SaveCredentials persists credentials to the specified store.
//
// When creds.HMACInKeyring is set, the HMAC Secret is written to the OS keychain
// (not the file) and stripped from the on-disk JSON; metadata (org, method,
// token, apikey) is still written to the home/project file. A keychain failure
// is returned so the caller can fall back to file storage.
func SaveCredentials(creds *Credentials, store CredentialStore) error {
	path, err := storePath(store)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Copy so we never mutate the caller's struct while stripping the secret.
	toWrite := *creds
	if toWrite.HMACInKeyring && toWrite.Secret != "" {
		if err := saveSecretToKeyring(hmacKeyringAccount(toWrite.OrgID), toWrite.Secret); err != nil {
			return err
		}
		toWrite.Secret = "" // keep the secret out of the file
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
		if creds, lerr := loadFromFile(store); lerr == nil && creds.HMACInKeyring {
			_ = removeSecretFromKeyring(hmacKeyringAccount(creds.OrgID))
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
		return "project (.vulnetix/credentials.json)"
	}
	if _, err := loadFromFile(StoreHome); err == nil {
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
	var lines []string

	if os.Getenv("VULNETIX_API_TOKEN") != "" {
		lines = append(lines, "env VULNETIX_API_TOKEN: set")
	} else {
		lines = append(lines, "env VULNETIX_API_TOKEN: not set")
	}

	if os.Getenv("VULNETIX_API_KEY") != "" && os.Getenv("VULNETIX_ORG_ID") != "" {
		lines = append(lines, "env VULNETIX_API_KEY + VULNETIX_ORG_ID: set")
	} else {
		lines = append(lines, "env VULNETIX_API_KEY + VULNETIX_ORG_ID: not set")
	}

	if os.Getenv("VVD_ORG") != "" && os.Getenv("VVD_SECRET") != "" {
		lines = append(lines, "env VVD_ORG + VVD_SECRET: set")
	} else {
		lines = append(lines, "env VVD_ORG + VVD_SECRET: not set")
	}

	if _, err := loadFromFile(StoreProject); err == nil {
		lines = append(lines, "project .vulnetix/credentials.json: found")
	} else {
		lines = append(lines, "project .vulnetix/credentials.json: not found")
	}

	if _, err := loadFromFile(StoreHome); err == nil {
		lines = append(lines, "home ~/.vulnetix/credentials.json: found")
	} else {
		lines = append(lines, "home ~/.vulnetix/credentials.json: not found")
	}

	netrc := NetrcStatus()
	switch {
	case !netrc.Found:
		lines = append(lines, fmt.Sprintf("netrc %s: not found", netrc.Path))
	case netrc.Err != nil:
		lines = append(lines, fmt.Sprintf("netrc %s: unusable (%s)", netrc.Path, netrc.Err))
	case netrc.MachineFound:
		lines = append(lines, fmt.Sprintf("netrc %s machine %s: found", netrc.Path, PackageFirewallHost))
	default:
		lines = append(lines, fmt.Sprintf("netrc %s machine %s: not found", netrc.Path, PackageFirewallHost))
	}

	lines = append(lines, packageFirewallConfigStatus())
	lines = append(lines, "Unauthenticated Community (VDB only): available")

	return lines
}

func packageFirewallConfigStatus() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "package firewall package-manager configs: unknown (" + err.Error() + ")"
	}
	var found []string
	for _, eco := range pfw.All() {
		if !eco.LiveWriter {
			continue
		}
		files, err := pfw.ConfigFiles(eco, pfw.ConfigOptions{
			HomeDir:  home,
			ProxyURL: "https://" + PackageFirewallHost,
			OrgID:    "org",
			APIKey:   "key",
		})
		if err != nil {
			continue
		}
		needle := pfw.ProxyURL("https://"+PackageFirewallHost, eco)
		for _, file := range files {
			data, err := os.ReadFile(file.Path)
			if err == nil && strings.Contains(string(data), needle) {
				found = append(found, eco.Command)
				break
			}
		}
	}
	if len(found) == 0 {
		return "package firewall package-manager configs: none found"
	}
	return "package firewall package-manager configs: " + strings.Join(found, ", ")
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

	// Hydrate the HMAC secret from the OS keychain when it lives there.
	if creds.HMACInKeyring && creds.Secret == "" {
		if secret, kerr := loadSecretFromKeyring(hmacKeyringAccount(creds.OrgID)); kerr == nil {
			creds.Secret = secret
		}
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
