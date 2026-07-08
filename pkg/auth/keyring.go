package auth

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/zalando/go-keyring"
)

// keyringService is the service name under which secrets are stored in the OS
// keychain (Windows Credential Manager, macOS Keychain, Linux Secret Service).
const keyringService = "vulnetix"

// KeychainSetupURL points users at documentation for enabling an OS keychain /
// Secret Service backend when none is detected.
const KeychainSetupURL = "https://vulnetix.com/docs/cli/keychain"

// keyringProbeAccount is a reserved account name used only to detect whether a
// usable keychain backend is present.
const keyringProbeAccount = "__vulnetix_probe__"

// KeyringAvailable reports whether a usable OS keychain backend is present.
// It returns nil when the keychain can be used, or a descriptive error (with
// OS-specific guidance and KeychainSetupURL) when it cannot — so callers can
// fall back to file storage and give the user actionable feedback.
//
// Detection: a Get on a non-existent probe account returns keyring.ErrNotFound
// when a backend is present (Windows/macOS always; Linux with a running Secret
// Service). Any other error means no usable backend for this GOOS.
func KeyringAvailable() error {
	_, err := keyring.Get(keyringService, keyringProbeAccount)
	if err == nil || errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return fmt.Errorf("no OS keychain backend detected on %s/%s: %w%s",
		runtime.GOOS, runtime.GOARCH, err, keychainHint())
}

// keychainHint returns OS-specific setup guidance appended to availability errors.
func keychainHint() string {
	var backend string
	switch runtime.GOOS {
	case "darwin":
		backend = "macOS Keychain (should always be available; try unlocking your login keychain)"
	case "windows":
		backend = "Windows Credential Manager (should always be available)"
	case "linux":
		backend = "a freedesktop Secret Service provider (GNOME Keyring / KWallet) running on the D-Bus session bus — headless sessions usually have none"
	default:
		backend = "a supported OS keychain"
	}
	return fmt.Sprintf("\n  expected: %s\n  setup guide: %s\n  alternatively store credentials in a file with --store home|project", backend, KeychainSetupURL)
}

// saveSecretToKeyring stores a secret under (keyringService, account).
func saveSecretToKeyring(account, secret string) error {
	if err := KeyringAvailable(); err != nil {
		return err
	}
	return keyring.Set(keyringService, account, secret)
}

// loadSecretFromKeyring retrieves a secret. Returns ("", nil) when the account
// has no stored secret, and an error only on a backend failure.
func loadSecretFromKeyring(account string) (string, error) {
	secret, err := keyring.Get(keyringService, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", nil
	}
	return secret, err
}

// loadRequiredSecretFromKeyring retrieves a secret that metadata says must
// exist in the keychain.
func loadRequiredSecretFromKeyring(account string) (string, error) {
	secret, err := keyring.Get(keyringService, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", fmt.Errorf("keyring entry %q not found", account)
	}
	return secret, err
}

// removeSecretFromKeyring deletes a stored secret. A missing entry is not an error.
func removeSecretFromKeyring(account string) error {
	err := keyring.Delete(keyringService, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}

// hmacKeyringAccount is the keychain account name for an org's HMAC secret.
func hmacKeyringAccount(orgID string) string {
	if orgID == "" {
		return "hmac-secret"
	}
	return "hmac-secret:" + orgID
}

// tokenKeyringAccount is the keychain account name for a Bearer token.
func tokenKeyringAccount(orgID string) string {
	if orgID == "" {
		return "token"
	}
	return "token:" + orgID
}

// apiKeyKeyringAccount is the keychain account name for a legacy API key.
func apiKeyKeyringAccount(orgID string) string {
	if orgID == "" {
		return "apikey"
	}
	return "apikey:" + orgID
}
