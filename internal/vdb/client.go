package vdb

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vulnetix/cli/internal/auth"
	"github.com/vulnetix/cli/internal/cache"
	"github.com/vulnetix/cli/internal/tty"
)

const (
	DefaultBaseURL     = "https://api.vdb.vulnetix.com"
	DefaultAPIVersion  = "/v1"
	Region             = "us-east-1"
	Service        = "vdb"
	Algorithm      = "AWS4-HMAC-SHA512"
	TokenExpiry    = 15 * time.Minute
	MaxRetries     = 2
	BaseBackoff    = 2 * time.Second
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
	BaseURL         string
	APIVersion      string
	OrgID           string
	SecretKey       string
	AuthMethod      auth.AuthMethod
	APIKey          string // hex digest for Direct API Key auth
	HTTPClient      *http.Client
	LastRateLimit   *RateLimitInfo
	LastCacheStatus string // "HIT", "MISS", "LOCAL", "REVALIDATED", or "" if no X-Cache header
	Cache           *cache.DiskCache
	NoCache         bool
	RefreshCache    bool
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

// NotFoundError is returned when the API responds with 404.
type NotFoundError struct {
	Message string
}

func (e *NotFoundError) Error() string {
	return e.Message
}

// sharedTransport is reused across clients for connection pooling.
var sharedTransport = &http.Transport{
	MaxIdleConns:        20,
	MaxIdleConnsPerHost: 10,
	IdleConnTimeout:     90 * time.Second,
}

// NewClient creates a new VDB API client using SigV4 auth
func NewClient(orgID, secretKey string) *Client {
	return &Client{
		BaseURL:    DefaultBaseURL,
		APIVersion: DefaultAPIVersion,
		OrgID:      orgID,
		SecretKey:  secretKey,
		AuthMethod: auth.SigV4,
		HTTPClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: sharedTransport,
		},
	}
}

// NewClientFromCredentials creates a VDB API client from centralized credentials
func NewClientFromCredentials(creds *auth.Credentials) *Client {
	return &Client{
		BaseURL:    DefaultBaseURL,
		APIVersion: DefaultAPIVersion,
		OrgID:      creds.OrgID,
		SecretKey:  creds.Secret,
		AuthMethod: creds.Method,
		APIKey:     creds.APIKey,
		HTTPClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: sharedTransport,
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
	url := c.BaseURL + c.APIVersion + path

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

// addAuthHeader resolves the authorization header and sets it on the request.
func (c *Client) addAuthHeader(req *http.Request) error {
	switch c.AuthMethod {
	case auth.DirectAPIKey:
		req.Header.Set("Authorization", fmt.Sprintf("ApiKey %s:%s", c.OrgID, c.APIKey))
	default:
		token, err := c.GetToken()
		if err != nil {
			return fmt.Errorf("failed to get token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return nil
}

// doRequestWithRetry executes an HTTP request with retry logic for transient errors.
// It captures rate limit and cache headers from the response.
func (c *Client) doRequestWithRetry(req *http.Request) ([]byte, error) {
	var lastErr error

	for attempt := 0; attempt <= MaxRetries; attempt++ {
		if attempt > 0 {
			backoff := BaseBackoff * time.Duration(1<<(attempt-1))
			curlHint := retryCurlHint(req)
			fmt.Fprintf(os.Stderr, "[vdb] retry %d/%d after %s: %v%s\n", attempt, MaxRetries, backoff, lastErr, curlHint)
			time.Sleep(backoff)

			// For retries, we need to re-read the body if present
			if req.GetBody != nil {
				newBody, err := req.GetBody()
				if err != nil {
					return nil, fmt.Errorf("failed to reset request body: %w", err)
				}
				req.Body = newBody
			}
		}

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			if isRetryableError(err) && attempt < MaxRetries {
				lastErr = err
				continue
			}
			return nil, fmt.Errorf("failed to execute request: %w", err)
		}

		// Capture rate limit and cache headers
		c.LastRateLimit = parseRateLimitHeaders(resp)
		c.LastCacheStatus = resp.Header.Get("X-Cache")

		responseBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read response: %w", err)
		}

		if isRetryableStatus(resp.StatusCode) && attempt < MaxRetries {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}

		if resp.StatusCode >= 400 {
			var errResp ErrorResponse
			if err := json.Unmarshal(responseBody, &errResp); err == nil {
				msg := fmt.Sprintf("API error (%d): %s - %s", resp.StatusCode, errResp.Error, errResp.Details)
				if resp.StatusCode == http.StatusNotFound {
					return nil, &NotFoundError{Message: msg}
				}
				return nil, fmt.Errorf("%s", msg)
			}
			msg := fmt.Sprintf("API error (%d): %s", resp.StatusCode, string(responseBody))
			if resp.StatusCode == http.StatusNotFound {
				return nil, &NotFoundError{Message: msg}
			}
			return nil, fmt.Errorf("%s", msg)
		}

		return responseBody, nil
	}

	return nil, fmt.Errorf("request failed after %d retries: %w", MaxRetries, lastErr)
}

// DoRequest performs an authenticated API request with retry for transient errors.
func (c *Client) DoRequest(method, path string, body interface{}) ([]byte, error) {
	// Marshal body once before retry loop
	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	url := c.BaseURL + c.APIVersion + path

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	if err := c.addAuthHeader(req); err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.NoCache || c.RefreshCache {
		req.Header.Set("Cache-Control", "no-cache")
	}

	// Add cache-busting query parameter when bypassing caches.
	// This ensures CloudFront treats it as a unique URL regardless of CDN config.
	if c.NoCache || c.RefreshCache {
		q := req.URL.Query()
		q.Set("_t", fmt.Sprintf("%d", time.Now().UnixMilli()))
		req.URL.RawQuery = q.Encode()
	}

	// Enable body reset for retries
	if body != nil {
		bodyBytes, _ := json.Marshal(body)
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBytes)), nil
		}
	}

	return c.doRequestWithRetry(req)
}

// doRequestWithRetryFull is like doRequestWithRetry but also returns status code and headers.
func (c *Client) doRequestWithRetryFull(req *http.Request) (body []byte, statusCode int, headers http.Header, err error) {
	var lastErr error

	for attempt := 0; attempt <= MaxRetries; attempt++ {
		if attempt > 0 {
			backoff := BaseBackoff * time.Duration(1<<(attempt-1))
			curlHint := retryCurlHint(req)
			fmt.Fprintf(os.Stderr, "[vdb] retry %d/%d after %s: %v%s\n", attempt, MaxRetries, backoff, lastErr, curlHint)
			time.Sleep(backoff)

			if req.GetBody != nil {
				newBody, bErr := req.GetBody()
				if bErr != nil {
					return nil, 0, nil, fmt.Errorf("failed to reset request body: %w", bErr)
				}
				req.Body = newBody
			}
		}

		resp, doErr := c.HTTPClient.Do(req)
		if doErr != nil {
			if isRetryableError(doErr) && attempt < MaxRetries {
				lastErr = doErr
				continue
			}
			return nil, 0, nil, fmt.Errorf("failed to execute request: %w", doErr)
		}

		c.LastRateLimit = parseRateLimitHeaders(resp)
		c.LastCacheStatus = resp.Header.Get("X-Cache")

		responseBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return nil, 0, nil, fmt.Errorf("failed to read response: %w", readErr)
		}

		if isRetryableStatus(resp.StatusCode) && attempt < MaxRetries {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}

		return responseBody, resp.StatusCode, resp.Header, nil
	}

	return nil, 0, nil, fmt.Errorf("request failed after %d retries: %w", MaxRetries, lastErr)
}

// DoRequestCached performs an authenticated, cached GET request.
// For non-GET or when cache is disabled, it falls through to DoRequest.
func (c *Client) DoRequestCached(method, path string, body interface{}, ttl time.Duration) ([]byte, error) {
	// Only cache GETs with a working cache
	if method != "GET" || c.Cache == nil || c.NoCache {
		return c.DoRequest(method, path, body)
	}

	key := cache.CacheKey(c.APIVersion, path)

	// Check cache (unless forced refresh)
	if !c.RefreshCache {
		if entry, ok := c.Cache.Get(key); ok && entry.IsFresh() {
			c.LastCacheStatus = "LOCAL"
			c.LastRateLimit = nil
			return entry.Body, nil
		}
	}

	// Build the request
	url := c.BaseURL + c.APIVersion + path
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	if err := c.addAuthHeader(req); err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	// Add conditional headers from stale cache entry
	if !c.RefreshCache {
		if entry, ok := c.Cache.Get(key); ok {
			if entry.ETag != "" {
				req.Header.Set("If-None-Match", entry.ETag)
			}
			if entry.LastModified != "" {
				req.Header.Set("If-Modified-Since", entry.LastModified)
			}
		}
	}

	respBody, statusCode, headers, err := c.doRequestWithRetryFull(req)
	if err != nil {
		return nil, err
	}

	// 304 Not Modified — refresh TTL and return cached body
	if statusCode == http.StatusNotModified {
		if entry, ok := c.Cache.Get(key); ok {
			entry.CachedAt = time.Now()
			entry.TTL = ttl
			c.Cache.Put(key, entry) //nolint:errcheck
			c.LastCacheStatus = "REVALIDATED"
			return entry.Body, nil
		}
	}

	if statusCode >= 400 {
		var errResp ErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			msg := fmt.Sprintf("API error (%d): %s - %s", statusCode, errResp.Error, errResp.Details)
			if statusCode == http.StatusNotFound {
				return nil, &NotFoundError{Message: msg}
			}
			return nil, fmt.Errorf("%s", msg)
		}
		msg := fmt.Sprintf("API error (%d): %s", statusCode, string(respBody))
		if statusCode == http.StatusNotFound {
			return nil, &NotFoundError{Message: msg}
		}
		return nil, fmt.Errorf("%s", msg)
	}

	// Never cache semantically empty responses (e.g. search with total: 0)
	// so they can't poison the local cache when the CDN returns stale data.
	if !isEmptyResponse(respBody) {
		entry := &cache.Entry{
			Body:         respBody,
			ETag:         headers.Get("ETag"),
			LastModified: headers.Get("Last-Modified"),
			CachedAt:     time.Now(),
			TTL:          ttl,
		}
		c.Cache.Put(key, entry) //nolint:errcheck
	}

	return respBody, nil
}

// isEmptyResponse returns true if body is a JSON object with "total": 0,
// indicating a semantically empty paginated result that should not be cached.
func isEmptyResponse(body []byte) bool {
	var envelope struct {
		Total *int `json:"total"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return false
	}
	return envelope.Total != nil && *envelope.Total == 0
}

// DoRequestRawBody performs an authenticated API request with a raw body (not JSON-marshaled).
func (c *Client) DoRequestRawBody(method, path string, body []byte, contentType string) ([]byte, error) {
	url := c.BaseURL + c.APIVersion + path

	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	if err := c.addAuthHeader(req); err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)

	// Enable body reset for retries
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}

	return c.doRequestWithRetry(req)
}

// DoRequestMultipart performs an authenticated multipart/form-data API request.
func (c *Client) DoRequestMultipart(path, filePath, fileField string, fields map[string]string) ([]byte, error) {
	// Read the file
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	// Build multipart body
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add form fields
	for k, v := range fields {
		if err := writer.WriteField(k, v); err != nil {
			return nil, fmt.Errorf("failed to write field %s: %w", k, err)
		}
	}

	// Add file field
	fileName := filepath.Base(filePath)
	part, err := writer.CreateFormFile(fileField, fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to create form file: %w", err)
	}
	if _, err := part.Write(fileData); err != nil {
		return nil, fmt.Errorf("failed to write file data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close multipart writer: %w", err)
	}

	bodyBytes := buf.Bytes()
	contentType := writer.FormDataContentType()

	url := c.BaseURL + c.APIVersion + path

	req, err := http.NewRequest("POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	if err := c.addAuthHeader(req); err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)

	// Enable body reset for retries
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(bodyBytes)), nil
	}

	return c.doRequestWithRetry(req)
}

// retryCurlHint returns a dim curl equivalent of req (no auth headers) for retry log lines.
// Returns an empty string when stderr is not a terminal.
func retryCurlHint(req *http.Request) string {
	if !tty.StderrIsTerminal() {
		return ""
	}
	method := req.Method
	rawURL := req.URL.String()
	// Strip the cache-busting _t param so the hint stays readable.
	if u, err := req.URL.Parse(rawURL); err == nil {
		q := u.Query()
		q.Del("_t")
		u.RawQuery = q.Encode()
		rawURL = u.String()
	}
	var cmd string
	if method == "GET" {
		cmd = fmt.Sprintf("curl -s %q", rawURL)
	} else {
		cmd = fmt.Sprintf("curl -s -X %s %q", method, rawURL)
	}
	const dim = "\033[2m"
	const reset = "\033[0m"
	return fmt.Sprintf("  %s%s%s", dim, cmd, reset)
}

// isRetryableError returns true for timeout and temporary network errors.
func isRetryableError(err error) bool {
	if os.IsTimeout(err) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "deadline exceeded") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset")
}

// isRetryableStatus returns true for gateway errors that indicate upstream unavailability.
func isRetryableStatus(code int) bool {
	return code == 502 || code == 503 || code == 504
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
