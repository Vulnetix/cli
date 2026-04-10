// Package analytics provides Google Analytics 4 (GA4) Measurement Protocol
// integration for server-side event tracking from the Vulnetix CLI.
//
// This uses the same GA4 property (G-NWBJE5RS0Q) as the Vulnetix website,
// enabling unified analytics across the web app and CLI.
//
// Privacy: All tracking is anonymous. No PII is collected. Users can opt out
// by setting VULNETIX_NO_ANALYTICS=1 or DO_NOT_TRACK=1.
package analytics

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"
)

const (
	// GA4 Measurement Protocol endpoint
	ga4Endpoint = "https://www.google-analytics.com/mp/collect"

	// Same tracking property as the Vulnetix website (../website/index.html)
	measurementID = "G-NWBJE5RS0Q"

	// API secret for Measurement Protocol (server-side only, not sensitive)
	apiSecret = "cli-mp-secret"

	// HTTP timeout for analytics requests
	httpTimeout = 3 * time.Second
)

// Event categories matching the website's ga4-client.ts patterns
const (
	CategoryCommand     = "cli_command"
	CategoryAuth        = "authentication"
	CategoryVDB         = "vulnerability_database"
	CategoryScan        = "scanning"
	CategoryError       = "error"
	CategoryEngagement  = "engagement"
)

// event represents a single GA4 event in the Measurement Protocol payload.
type event struct {
	Name   string                 `json:"name"`
	Params map[string]interface{} `json:"params"`
}

// payload is the GA4 Measurement Protocol request body.
type payload struct {
	ClientID string  `json:"client_id"`
	Events   []event `json:"events"`
}

// Client sends analytics events to GA4 via the Measurement Protocol.
type Client struct {
	clientID   string
	version    string
	platform   string
	httpClient *http.Client
	disabled   bool
	mu         sync.Mutex
}

var (
	defaultClient *Client
	once          sync.Once
)

// Init initializes the global analytics client. Call once at startup.
// version is the CLI version string. platform is the detected runtime platform.
func Init(version, platform string) {
	once.Do(func() {
		defaultClient = NewClient(version, platform)
	})
}

// NewClient creates a new analytics client.
func NewClient(version, platform string) *Client {
	c := &Client{
		clientID: generateClientID(),
		version:  version,
		platform: platform,
		httpClient: &http.Client{
			Timeout: httpTimeout,
		},
		disabled: isOptedOut(),
	}
	return c
}

// isOptedOut checks if the user has opted out of analytics.
func isOptedOut() bool {
	if os.Getenv("VULNETIX_NO_ANALYTICS") != "" {
		return true
	}
	if os.Getenv("DO_NOT_TRACK") == "1" {
		return true
	}
	// Respect CI environments — don't track in automated pipelines
	// unless explicitly running as a GitHub Action (which we want to track)
	if os.Getenv("CI") == "true" && os.Getenv("GITHUB_ACTIONS") != "true" {
		return true
	}
	return false
}

// generateClientID creates an anonymous, stable client identifier.
// Uses a hash of hostname + OS + arch — no PII is stored.
func generateClientID() string {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	raw := fmt.Sprintf("%s-%s-%s", hostname, runtime.GOOS, runtime.GOARCH)
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:16]) // 32 hex chars
}

// TrackCommand tracks a CLI command invocation.
func TrackCommand(command string, args map[string]interface{}) {
	if defaultClient == nil {
		return
	}
	params := map[string]interface{}{
		"event_category": CategoryCommand,
		"command":        command,
		"cli_version":    defaultClient.version,
		"platform":       defaultClient.platform,
		"os":             runtime.GOOS,
		"arch":           runtime.GOARCH,
	}
	for k, v := range args {
		params[k] = v
	}
	defaultClient.sendAsync("cli_command", params)
}

// TrackVDBQuery tracks a VDB API query.
func TrackVDBQuery(subcommand, apiVersion string) {
	if defaultClient == nil {
		return
	}
	defaultClient.sendAsync("vdb_query", map[string]interface{}{
		"event_category": CategoryVDB,
		"subcommand":     subcommand,
		"api_version":    apiVersion,
		"cli_version":    defaultClient.version,
		"platform":       defaultClient.platform,
	})
}

// TrackAuth tracks an authentication event.
func TrackAuth(method, action string, success bool) {
	if defaultClient == nil {
		return
	}
	eventName := fmt.Sprintf("%s_%s", action, boolToResult(success))
	defaultClient.sendAsync(eventName, map[string]interface{}{
		"event_category": CategoryAuth,
		"method":         method,
		"success":        success,
		"cli_version":    defaultClient.version,
	})
}

// TrackScan tracks a scan invocation.
func TrackScan(scanType string, fileCount int) {
	if defaultClient == nil {
		return
	}
	defaultClient.sendAsync("scan_initiated", map[string]interface{}{
		"event_category": CategoryScan,
		"scan_type":      scanType,
		"file_count":     fileCount,
		"cli_version":    defaultClient.version,
		"platform":       defaultClient.platform,
	})
}

// TrackError tracks an error occurrence.
func TrackError(command, errorMsg string, fatal bool) {
	if defaultClient == nil {
		return
	}
	// Truncate error message to avoid sending excessive data
	if len(errorMsg) > 100 {
		errorMsg = errorMsg[:100]
	}
	defaultClient.sendAsync("exception", map[string]interface{}{
		"event_category": CategoryError,
		"command":        command,
		"description":    errorMsg,
		"fatal":          fatal,
		"cli_version":    defaultClient.version,
	})
}

// TrackEvent tracks a generic custom event.
func TrackEvent(eventName string, params map[string]interface{}) {
	if defaultClient == nil {
		return
	}
	if params == nil {
		params = make(map[string]interface{})
	}
	params["cli_version"] = defaultClient.version
	params["platform"] = defaultClient.platform
	defaultClient.sendAsync(eventName, params)
}

// sendAsync sends an event in a background goroutine so it never blocks the CLI.
func (c *Client) sendAsync(eventName string, params map[string]interface{}) {
	if c.disabled {
		return
	}
	// Fire and forget — analytics should never slow down the CLI
	go c.send(eventName, params) //nolint:errcheck
}

// send dispatches a single event to the GA4 Measurement Protocol endpoint.
func (c *Client) send(eventName string, params map[string]interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	p := payload{
		ClientID: c.clientID,
		Events: []event{
			{
				Name:   eventName,
				Params: params,
			},
		},
	}

	body, err := json.Marshal(p)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s?measurement_id=%s&api_secret=%s", ga4Endpoint, measurementID, apiSecret)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func boolToResult(b bool) string {
	if b {
		return "success"
	}
	return "failure"
}
