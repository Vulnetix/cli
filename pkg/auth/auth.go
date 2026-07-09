package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// AuthMethod represents the authentication method to use
type AuthMethod string

const (
	// DirectAPIKey uses a pre-computed API key hex digest sent as ApiKey header
	DirectAPIKey AuthMethod = "apikey"
	// SigV4 uses AWS Signature Version 4 for token exchange
	SigV4 AuthMethod = "sigv4"
	// Token uses an Authentik API token ("Tokens and App passwords") sent as a
	// Bearer header. This is the current, self-service credential; apikey/sigv4
	// are legacy.
	Token AuthMethod = "token"
)

// ValidateMethod checks if the given string is a valid AuthMethod
func ValidateMethod(method string) (AuthMethod, error) {
	switch AuthMethod(method) {
	case DirectAPIKey:
		return DirectAPIKey, nil
	case SigV4:
		return SigV4, nil
	case Token:
		return Token, nil
	default:
		return "", fmt.Errorf("invalid auth method %q: must be 'token', 'apikey', or 'sigv4'", method)
	}
}

// CredentialStore represents where credentials are persisted
type CredentialStore string

const (
	StoreHome    CredentialStore = "home"    // ~/.vulnetix/credentials.json
	StoreProject CredentialStore = "project" // .vulnetix/credentials.json
	StoreKeyring CredentialStore = "keyring" // system keyring (stub)
)

// ValidateStore checks if the given string is a valid CredentialStore
func ValidateStore(store string) (CredentialStore, error) {
	switch CredentialStore(store) {
	case StoreHome:
		return StoreHome, nil
	case StoreProject:
		return StoreProject, nil
	case StoreKeyring:
		return StoreKeyring, nil
	default:
		return "", fmt.Errorf("invalid store %q: must be 'home', 'project', or 'keyring'", store)
	}
}

// Credentials holds authentication credentials for the Vulnetix API
type Credentials struct {
	OrgID  string     `json:"org_id"`
	APIKey string     `json:"api_key,omitempty"` // hex digest for Direct API Key
	Secret string     `json:"secret,omitempty"`  // secret key for SigV4 (Authentik-sourced HMAC secret)
	Token  string     `json:"token,omitempty"`   // Authentik API token (Bearer)
	Method AuthMethod `json:"method"`

	// HMACInKeyring is true when the SigV4/HMAC Secret is stored in the OS
	// keychain rather than inline in this credentials file. When set, Secret is
	// empty on disk and hydrated from the keychain at load time.
	HMACInKeyring bool `json:"hmac_in_keyring,omitempty"`

	// TokenInKeyring and APIKeyInKeyring mirror HMACInKeyring for Bearer and
	// legacy ApiKey credentials. The credential file keeps only metadata.
	TokenInKeyring  bool `json:"token_in_keyring,omitempty"`
	APIKeyInKeyring bool `json:"api_key_in_keyring,omitempty"`
}

// GetAuthHeader returns the Authorization header value for the given credentials
func GetAuthHeader(creds *Credentials) string {
	switch creds.Method {
	case Token:
		return "Bearer " + creds.Token
	case DirectAPIKey:
		return fmt.Sprintf("ApiKey %s:%s", creds.OrgID, creds.APIKey)
	case SigV4:
		// The upload endpoints (vdb-site) accept the derived ApiKey; send that
		// instead of exchanging a cross-service JWT. ApiKey = HMAC-SHA256(secret, org).
		mac := hmac.New(sha256.New, []byte(creds.Secret))
		mac.Write([]byte(creds.OrgID))
		return fmt.Sprintf("ApiKey %s:%s", creds.OrgID, hex.EncodeToString(mac.Sum(nil)))
	default:
		return ""
	}
}
