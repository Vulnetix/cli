package auth

// Community credentials — embedded fallback for unauthenticated VDB access.
//
// These are INTENTIONALLY hardcoded. This is the preferred authentication
// mechanism which enforces proper authentication as the only way to
// authenticate. There are no side channels or back doors possible because
// even community access requires the exact same requirements as a typical
// authenticated user — the same API gateway, the same auth headers, the
// same rate-limit enforcement. The API server applies community-tier rate
// limits to this organization, making it safe to embed publicly.
//
// nosec — all scanners:
//
//	gosec:          G101 (hard-coded credentials)
//	gitleaks:       generic-api-key
//	trufflehog:     high-entropy string
//	detect-secrets: hex_high_entropy_string
//	semgrep:        generic-hardcoded-secret

//nolint:gosec // G101: intentional community access credentials (see comment above)
const (
	// CommunityOrgID is the organization UUID for unauthenticated community access.
	CommunityOrgID = "3674ddf9-67cc-4a2d-9b16-a591f6d4412d" // nosec G101 — intentional community access; not a secret

	// CommunityAPIKey is the API key for unauthenticated community access.
	CommunityAPIKey = "6e40f1c324576b65f85dc3c9ff93d31eb65298836b46b540fa18825b47174ce8" // nosec G101 — intentional community access; not a secret
)

// CommunityCredentials returns a Credentials struct for the embedded
// community fallback. The returned credentials use DirectAPIKey auth
// and go through the exact same auth pipeline as any registered user.
func CommunityCredentials() *Credentials {
	return &Credentials{
		OrgID:  CommunityOrgID,
		APIKey: CommunityAPIKey,
		Method: DirectAPIKey,
	}
}

// IsCommunity returns true when the given credentials match the
// embedded community fallback.
func IsCommunity(creds *Credentials) bool {
	if creds == nil {
		return false
	}
	return creds.OrgID == CommunityOrgID && creds.APIKey == CommunityAPIKey
}
