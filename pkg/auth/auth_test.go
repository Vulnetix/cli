package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestValidateMethod_Valid(t *testing.T) {
	tests := []struct {
		input    string
		expected AuthMethod
	}{
		{"apikey", DirectAPIKey},
		{"sigv4", SigV4},
	}
	for _, tc := range tests {
		got, err := ValidateMethod(tc.input)
		if err != nil {
			t.Errorf("ValidateMethod(%q): unexpected error: %v", tc.input, err)
		}
		if got != tc.expected {
			t.Errorf("ValidateMethod(%q): expected %q, got %q", tc.input, tc.expected, got)
		}
	}
}

func TestValidateMethod_Invalid(t *testing.T) {
	for _, input := range []string{"", "jwt", "basic", "none"} {
		_, err := ValidateMethod(input)
		if err == nil {
			t.Errorf("ValidateMethod(%q): expected error", input)
		}
	}
}

func TestValidateStore_Valid(t *testing.T) {
	tests := []struct {
		input    string
		expected CredentialStore
	}{
		{"home", StoreHome},
		{"project", StoreProject},
	}
	for _, tc := range tests {
		got, err := ValidateStore(tc.input)
		if err != nil {
			t.Errorf("ValidateStore(%q): unexpected error: %v", tc.input, err)
		}
		if got != tc.expected {
			t.Errorf("ValidateStore(%q): expected %q, got %q", tc.input, tc.expected, got)
		}
	}
}

func TestValidateStore_Keyring(t *testing.T) {
	store, err := ValidateStore("keyring")
	if err != nil {
		t.Fatalf("unexpected error for keyring: %v", err)
	}
	if store != StoreKeyring {
		t.Fatalf("expected StoreKeyring, got %q", store)
	}
}

func TestValidateStore_Invalid(t *testing.T) {
	for _, input := range []string{"", "file", "memory"} {
		_, err := ValidateStore(input)
		if err == nil {
			t.Errorf("ValidateStore(%q): expected error", input)
		}
	}
}

func TestGetAuthHeader_DirectAPIKey(t *testing.T) {
	creds := &Credentials{
		OrgID:  "test-org",
		APIKey: "test-key",
		Method: DirectAPIKey,
	}
	header := GetAuthHeader(creds)
	if header != "ApiKey test-org:test-key" {
		t.Errorf("expected 'ApiKey test-org:test-key', got %q", header)
	}
}

func TestGetAuthHeader_SigV4(t *testing.T) {
	creds := &Credentials{
		OrgID:  "test-org",
		Secret: "secret",
		Method: SigV4,
	}
	// SigV4 sends the derived ApiKey for endpoints that accept ApiKey (uploads):
	// ApiKey <org>:<HMAC-SHA256(secret, org)>.
	mac := hmac.New(sha256.New, []byte("secret"))
	mac.Write([]byte("test-org"))
	want := "ApiKey test-org:" + hex.EncodeToString(mac.Sum(nil))
	if header := GetAuthHeader(creds); header != want {
		t.Errorf("expected %q for SigV4, got %q", want, header)
	}
}

func TestGetAuthHeader_UnknownMethod(t *testing.T) {
	creds := &Credentials{
		OrgID:  "test-org",
		Method: "unknown",
	}
	header := GetAuthHeader(creds)
	if header != "" {
		t.Errorf("expected empty header for unknown method, got %q", header)
	}
}

func TestCommunityCredentials(t *testing.T) {
	creds := CommunityCredentials()
	if creds == nil {
		t.Fatal("expected non-nil credentials")
	}
	if creds.OrgID != CommunityOrgID {
		t.Errorf("expected org ID %q, got %q", CommunityOrgID, creds.OrgID)
	}
	if creds.APIKey != CommunityAPIKey {
		t.Errorf("expected API key %q, got %q", CommunityAPIKey, creds.APIKey)
	}
	if creds.Method != DirectAPIKey {
		t.Errorf("expected method %q, got %q", DirectAPIKey, creds.Method)
	}
}

func TestIsCommunity(t *testing.T) {
	if IsCommunity(nil) {
		t.Fatal("nil credentials should not be community")
	}
	if !IsCommunity(CommunityCredentials()) {
		t.Fatal("community credentials should match")
	}
	if IsCommunity(&Credentials{
		OrgID:  "other",
		APIKey: CommunityAPIKey,
		Method: DirectAPIKey,
	}) {
		t.Fatal("different org should not match")
	}
	if IsCommunity(&Credentials{
		OrgID:  CommunityOrgID,
		APIKey: "other",
		Method: DirectAPIKey,
	}) {
		t.Fatal("different API key should not match")
	}
}

// The GUI presents an ApiKey as "<orgId>:<hex>". `auth login` stripped that
// prefix but the environment-variable path did not, so CI sent
// "ApiKey <org>:<org>:<hex>" and got HTTP 401 while a local login worked.
func TestGetAuthHeader_StripsPastedOrgPrefix(t *testing.T) {
	const org = "8ff8f1e4-0000-4000-8000-000000000000"
	const hexKey = "6e40f1c324576b65f85dc3c9ff93d31e"
	want := "ApiKey " + org + ":" + hexKey

	for name, key := range map[string]string{
		"bare hex digest": hexKey,
		"GUI <org>:<hex>": org + ":" + hexKey,
	} {
		t.Run(name, func(t *testing.T) {
			got := GetAuthHeader(&Credentials{OrgID: org, APIKey: key, Method: DirectAPIKey})
			if got != want {
				t.Errorf("GetAuthHeader() = %q, want %q", got, want)
			}
		})
	}
}

func TestStripOrgPrefix(t *testing.T) {
	const org = "org-uuid"
	cases := map[string]struct{ in, want string }{
		"strips exact prefix":     {org + ":abc", "abc"},
		"leaves bare key":         {"abc", "abc"},
		"leaves other org prefix": {"other:abc", "other:abc"},
		"empty org is a no-op":    {"abc", "abc"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			o := org
			if name == "empty org is a no-op" {
				o = ""
			}
			if got := StripOrgPrefix(o, tc.in); got != tc.want {
				t.Errorf("StripOrgPrefix(%q, %q) = %q, want %q", o, tc.in, got, tc.want)
			}
		})
	}
}
