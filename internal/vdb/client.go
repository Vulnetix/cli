package vdb

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/vulnetix/cli/internal/auth"
)

const (
	DefaultBaseURL = "https://api.vdb.vulnetix.com/v1"
	Region         = "us-east-1"
	Service        = "vdb"
	Algorithm      = "AWS4-HMAC-SHA512"
	TokenExpiry    = 15 * time.Minute
)

// RateLimitInfo holds rate limit data returned in API response headers.
type RateLimitInfo struct {
	MinuteLimit   int
	Remaining     int
	Reset         int
	WeekLimit     int
	WeekRemaining int
	WeekReset     int
	Present       bool
}

// Client represents a VDB API client
type Client struct {
	BaseURL       string
	OrgID         string
	SecretKey     string
	AuthMethod    auth.AuthMethod
	APIKey        string // hex digest for Direct API Key auth
	HTTPClient    *http.Client
	LastRateLimit *RateLimitInfo
	token         *TokenCache
	tokenMutex    sync.RWMutex
}

// TokenCache stores the JWT token and its expiration
type TokenCache struct {
	Token     string
	ExpiresAt time.Time
}

// TokenResponse represents the JWT token response
type TokenResponse struct {
	Token string `json:"token"`
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Exp   int64  `json:"exp"`
}

// ErrorResponse represents an API error response
type ErrorResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}

// NewClient creates a new VDB API client using SigV4 auth
func NewClient(orgID, secretKey string) *Client {
	return &Client{
		BaseURL:    DefaultBaseURL,
		OrgID:      orgID,
		SecretKey:  secretKey,
		AuthMethod: auth.SigV4,
		HTTPClient: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

// NewClientFromCredentials creates a VDB API client from centralized credentials
func NewClientFromCredentials(creds *auth.Credentials) *Client {
	return &Client{
		BaseURL:    DefaultBaseURL,
		OrgID:      creds.OrgID,
		SecretKey:  creds.Secret,
		AuthMethod: creds.Method,
		APIKey:     creds.APIKey,
		HTTPClient: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

// GetToken retrieves a valid JWT token (from cache or by requesting a new one)
func (c *Client) GetToken() (string, error) {
	// Check if we have a valid cached token with read lock
	c.tokenMutex.RLock()
	if c.token != nil && time.Now().Before(c.token.ExpiresAt.Add(-3*time.Minute)) {
		token := c.token.Token
		c.tokenMutex.RUnlock()
		return token, nil
	}
	c.tokenMutex.RUnlock()

	// Request a new token with write lock
	c.tokenMutex.Lock()
	defer c.tokenMutex.Unlock()

	// Double-check after acquiring write lock (another goroutine may have refreshed)
	if c.token != nil && time.Now().Before(c.token.ExpiresAt.Add(-3*time.Minute)) {
		return c.token.Token, nil
	}

	// Request a new token
	return c.requestNewTokenLocked()
}

// requestNewTokenLocked requests a new JWT token using AWS SigV4 authentication
// Caller must hold tokenMutex write lock
func (c *Client) requestNewTokenLocked() (string, error) {
	path := "/auth/token"
	url := c.BaseURL + path

	// Create the request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Sign the request with AWS SigV4
	if err := c.signRequest(req, path, ""); err != nil {
		return "", fmt.Errorf("failed to sign request: %w", err)
	}

	// Execute the request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Check for errors
	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := json.Unmarshal(body, &errResp); err == nil {
			return "", fmt.Errorf("API error (%d): %s - %s", resp.StatusCode, errResp.Error, errResp.Details)
		}
		return "", fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
	}

	// Parse the response
	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	// Cache the token
	c.token = &TokenCache{
		Token:     tokenResp.Token,
		ExpiresAt: time.Unix(tokenResp.Exp, 0),
	}

	return tokenResp.Token, nil
}

// signRequest signs an HTTP request using AWS Signature Version 4 (SHA-512)
func (c *Client) signRequest(req *http.Request, path, body string) error {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	// Add the X-Amz-Date header
	req.Header.Set("X-Amz-Date", amzDate)

	// Calculate payload hash
	payloadHash := sha512Hash(body)

	// Create canonical request
	canonicalHeaders := fmt.Sprintf("x-amz-date:%s\n", amzDate)
	signedHeaders := "x-amz-date"
	canonicalQueryString := "" // Empty for auth endpoint, can be extended for other endpoints

	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		req.Method,
		path,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	)

	// Create string to sign
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, Region, Service)
	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s",
		Algorithm,
		amzDate,
		credentialScope,
		sha512Hash(canonicalRequest),
	)

	// Calculate signature
	signingKey := getSignatureKey(c.SecretKey, dateStamp, Region, Service)
	signature := hex.EncodeToString(hmacSHA512(signingKey, stringToSign))

	// Create authorization header
	authHeader := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		Algorithm,
		c.OrgID,
		credentialScope,
		signedHeaders,
		signature,
	)

	req.Header.Set("Authorization", authHeader)
	return nil
}

// DoRequest performs an authenticated API request
func (c *Client) DoRequest(method, path string, body interface{}) ([]byte, error) {
	// Prepare request body
	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	// Create the request
	url := c.BaseURL + path
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set auth header based on method
	switch c.AuthMethod {
	case auth.DirectAPIKey:
		req.Header.Set("Authorization", fmt.Sprintf("ApiKey %s:%s", c.OrgID, c.APIKey))
	default:
		// SigV4: get a valid Bearer token
		token, err := c.GetToken()
		if err != nil {
			return nil, fmt.Errorf("failed to get token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}

	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Capture rate limit headers
	c.LastRateLimit = parseRateLimitHeaders(resp)

	// Read the response
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check for errors
	if resp.StatusCode >= 400 {
		var errResp ErrorResponse
		if err := json.Unmarshal(responseBody, &errResp); err == nil {
			return nil, fmt.Errorf("API error (%d): %s - %s", resp.StatusCode, errResp.Error, errResp.Details)
		}
		return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, string(responseBody))
	}

	return responseBody, nil
}

// parseRateLimitHeaders extracts rate limit info from response headers.
// Returns nil if none of the expected headers are present.
func parseRateLimitHeaders(resp *http.Response) *RateLimitInfo {
	headerMap := map[string]*int{}
	info := &RateLimitInfo{}
	headerMap["RateLimit-MinuteLimit"] = &info.MinuteLimit
	headerMap["RateLimit-Remaining"] = &info.Remaining
	headerMap["RateLimit-Reset"] = &info.Reset
	headerMap["RateLimit-WeekLimit"] = &info.WeekLimit
	headerMap["RateLimit-WeekRemaining"] = &info.WeekRemaining
	headerMap["RateLimit-WeekReset"] = &info.WeekReset

	found := false
	for header, field := range headerMap {
		if v := resp.Header.Get(header); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				*field = n
				found = true
			}
		}
	}
	if !found {
		return nil
	}
	info.Present = true
	return info
}

// Helper functions

func sha512Hash(data string) string {
	hash := sha512.Sum512([]byte(data))
	return hex.EncodeToString(hash[:])
}

func hmacSHA512(key []byte, data string) []byte {
	h := hmac.New(sha512.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func getSignatureKey(key, dateStamp, region, service string) []byte {
	kDate := hmacSHA512([]byte("AWS4"+key), dateStamp)
	kRegion := hmacSHA512(kDate, region)
	kService := hmacSHA512(kRegion, service)
	kSigning := hmacSHA512(kService, "aws4_request")
	return kSigning
}

// LoadCredentials loads VDB credentials using the centralized auth package.
// Returns orgID and secretKey for backward compatibility with existing callers.
func LoadCredentials() (orgID, secretKey string, err error) {
	creds, err := auth.LoadCredentials()
	if err != nil {
		return "", "", err
	}
	return creds.OrgID, creds.Secret, nil
}

// LoadFullCredentials loads credentials as a full Credentials struct
func LoadFullCredentials() (*auth.Credentials, error) {
	return auth.LoadCredentials()
}
