package auth

import (
	"strings"
	"testing"
)

func TestKeyringRoundtrip(t *testing.T) {
	if err := KeyringAvailable(); err != nil {
		t.Skipf("no OS keychain backend available: %v", err)
	}
	acct := hmacKeyringAccount("test-org-roundtrip")
	const secret = "s3cr3t-hmac-value-1234"

	if err := saveSecretToKeyring(acct, secret); err != nil {
		t.Fatalf("saveSecretToKeyring: %v", err)
	}
	t.Cleanup(func() { _ = removeSecretFromKeyring(acct) })

	got, err := loadSecretFromKeyring(acct)
	if err != nil {
		t.Fatalf("loadSecretFromKeyring: %v", err)
	}
	if got != secret {
		t.Fatalf("roundtrip mismatch: got %q want %q", got, secret)
	}

	if err := removeSecretFromKeyring(acct); err != nil {
		t.Fatalf("removeSecretFromKeyring: %v", err)
	}
	// Missing key reads as empty, no error; deleting again is a no-op.
	if got, err := loadSecretFromKeyring(acct); err != nil || got != "" {
		t.Fatalf("after delete: got %q err %v; want empty", got, err)
	}
	if err := removeSecretFromKeyring(acct); err != nil {
		t.Fatalf("re-delete should be a no-op, got %v", err)
	}
}

func TestKeychainHintMentionsSetupURL(t *testing.T) {
	if !strings.Contains(keychainHint(), KeychainSetupURL) {
		t.Errorf("keychain hint should reference the setup URL %q", KeychainSetupURL)
	}
}

func TestHMACKeyringAccount(t *testing.T) {
	if got := hmacKeyringAccount(""); got != "hmac-secret" {
		t.Errorf("empty org: got %q", got)
	}
	if got := hmacKeyringAccount("abc"); got != "hmac-secret:abc" {
		t.Errorf("org abc: got %q", got)
	}
}
