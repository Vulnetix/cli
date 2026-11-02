package github

// Client is the shared GitHub REST client for publishing into GitHub (code
// scanning, the dependency graph, repository advisories, release assets).
//
// It reads GITHUB_API_URL, so it works against GitHub Enterprise Server
// without configuration; sends JSON; follows Link rel="next" pagination; and
// waits out a rate limit when GitHub says how long, within a bound, rather
// than failing a publish at the end of a long scan for a minute's quota.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DefaultAPIURL is github.com's REST endpoint.
const DefaultAPIURL = "https://api.github.com"

// APIURL is GITHUB_API_URL, or github.com's.
func APIURL() string {
	if u := strings.TrimSpace(os.Getenv("GITHUB_API_URL")); u != "" {
		return strings.TrimRight(u, "/")
	}
	return DefaultAPIURL
}

// Client makes authenticated GitHub REST calls.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
	// MaxWait bounds the time one request spends waiting out rate limits.
	MaxWait time.Duration
	// Calls counts requests made.
	Calls int
}

// NewClient returns a client for GITHUB_API_URL with token.
func NewClient(token string) *Client {
	return &Client{
		BaseURL: APIURL(),
		Token:   token,
		HTTP:    &http.Client{Timeout: 60 * time.Second},
		MaxWait: 90 * time.Second,
	}
}

// APIError is a non-2xx answer.
type APIError struct {
	Method, Path string
	Status       int
	Message      string
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	return fmt.Sprintf("GitHub %s %s: HTTP %d: %s", e.Method, e.Path, e.Status, msg)
}

// IsStatus reports whether err is an APIError with one of the statuses.
func IsStatus(err error, statuses ...int) bool {
	var ae *APIError
	if !errors.As(err, &ae) {
		return false
	}
	for _, s := range statuses {
		if ae.Status == s {
			return true
		}
	}
	return false
}

// IsPermission reports a refusal that more permissions would fix: 401, 403
// (not a rate limit) or 404, which GitHub answers for a resource the token
// cannot see. Publishing treats these as warnings.
func IsPermission(err error) bool {
	return IsStatus(err, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound)
}

// ErrRateLimited is returned when the rate limit outlasts MaxWait.
var ErrRateLimited = errors.New("GitHub API rate limit exhausted")

// Do sends body (JSON-encoded unless it is []byte or nil) and decodes a JSON
// answer into out (when non-nil). It returns the response headers.
func (c *Client) Do(ctx context.Context, method, path string, body, out any) (http.Header, error) {
	var payload []byte
	switch b := body.(type) {
	case nil:
	case []byte:
		payload = b
	default:
		var err error
		if payload, err = json.Marshal(b); err != nil {
			return nil, err
		}
	}
	var waited time.Duration
	backoff := time.Second
	for attempt := 0; ; attempt++ {
		hdr, wait, err := c.once(ctx, method, path, payload, out)
		if !errors.Is(err, ErrRateLimited) {
			return hdr, err
		}
		if wait <= 0 {
			wait = backoff
			backoff *= 2
		}
		if attempt >= 5 || waited+wait > c.MaxWait {
			return hdr, err
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return hdr, ctx.Err()
		case <-t.C:
		}
		waited += wait
	}
}

func (c *Client) url(path string) string {
	if strings.HasPrefix(path, "https://") || strings.HasPrefix(path, "http://") {
		return path
	}
	base := c.BaseURL
	if base == "" {
		base = DefaultAPIURL
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return strings.TrimRight(base, "/") + path
}

func (c *Client) once(ctx context.Context, method, path string, payload []byte, out any) (http.Header, time.Duration, error) {
	var rd io.Reader
	if payload != nil {
		rd = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.url(path), rd)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	c.Calls++
	resp, err := hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			if resp.Header.Get("X-RateLimit-Remaining") == "0" || resp.Header.Get("Retry-After") != "" {
				return resp.Header, rateWait(resp.Header, time.Now()), ErrRateLimited
			}
		}
		var m struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &m)
		if m.Message == "" {
			m.Message = strings.TrimSpace(string(raw))
		}
		return resp.Header, 0, &APIError{Method: method, Path: path, Status: resp.StatusCode, Message: m.Message}
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(out); err != nil && !errors.Is(err, io.EOF) {
			return resp.Header, 0, fmt.Errorf("decode %s %s: %w", method, path, err)
		}
	}
	return resp.Header, 0, nil
}

// rateWait reads Retry-After, then X-RateLimit-Reset.
func rateWait(h http.Header, now time.Time) time.Duration {
	if s := h.Get("Retry-After"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			return time.Duration(n) * time.Second
		}
	}
	if s := h.Get("X-RateLimit-Reset"); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			if d := time.Unix(n, 0).Sub(now); d > 0 {
				return d + time.Second
			}
		}
	}
	return 0
}

var linkNext = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// GetAll fetches every page of a list endpoint and decodes the concatenated
// items into out (a pointer to a slice).
func (c *Client) GetAll(ctx context.Context, path string, out any) error {
	var all []json.RawMessage
	next := path
	for page := 0; next != "" && page < 100; page++ {
		var items []json.RawMessage
		hdr, err := c.Do(ctx, http.MethodGet, next, nil, &items)
		if err != nil {
			return err
		}
		all = append(all, items...)
		next = ""
		if m := linkNext.FindStringSubmatch(hdr.Get("Link")); len(m) == 2 {
			next = m[1]
		}
	}
	raw, err := json.Marshal(all)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}
