// Package tea is a client for the OWASP Transparency Exchange API.
//
// It speaks both halves of the same API: the consumption operations any
// conformant server serves, and the publication operations that create the
// objects those consumers read. That is deliberate — they are one API at one
// root, and a client that treated them as two would have to be told twice
// which server it is talking to.
//
// The default server is Vulnetix, but nothing here assumes it. A --server
// pointing at another organisation's TEA endpoint works for every read; writes
// will simply be refused by a server that does not know the caller, which is
// the correct outcome rather than something to guard against locally.
package tea

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vulnetix/cli/v3/pkg/auth"
)

// DefaultServer is Vulnetix's own TEA root. It is the `rootUrl` advertised in
// https://vulnetix.com/.well-known/tea.
const DefaultServer = "https://www.vulnetix.com/tea/v1"

// Client talks to one TEA server.
type Client struct {
	BaseURL string
	Creds   *auth.Credentials
	HTTP    *http.Client
}

// New builds a client. Credentials may be nil: the consumption operations of a
// public catalogue need none, and requiring them would make the CLI useless for
// reading somebody else's open transparency log.
func New(baseURL string, creds *auth.Credentials) *Client {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = DefaultServer
	}
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Creds:   creds,
		HTTP:    &http.Client{Timeout: 120 * time.Second},
	}
}

// Error is a TEA error response, in either the consumption or publication
// envelope. Both carry a machine-readable code; only the publication one
// carries a message and field.
type Error struct {
	Status  int    `json:"-"`
	Code    string `json:"error"`
	Message string `json:"message,omitempty"`
	Field   string `json:"field,omitempty"`
}

func (e *Error) Error() string {
	switch {
	case e.Message != "" && e.Field != "":
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Field)
	case e.Message != "":
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	case e.Code != "":
		return e.Code
	default:
		return fmt.Sprintf("HTTP %d", e.Status)
	}
}

// IsNotFound reports whether the server said the object does not exist, under
// either envelope's spelling.
func (e *Error) IsNotFound() bool {
	return e.Status == http.StatusNotFound ||
		e.Code == "OBJECT_UNKNOWN" || e.Code == "OBJECT_NOT_FOUND"
}

// Do performs one request and decodes the result into out.
//
// headers are applied last so a caller can set Idempotency-Key and
// Content-Digest, which are the two the publication API acts on and which a
// generic client would otherwise have no way to send.
func (c *Client) Do(ctx context.Context, method, path string, body any, out any, headers map[string]string) error {
	var reader io.Reader
	var raw []byte

	switch b := body.(type) {
	case nil:
	case []byte:
		raw = b
		reader = bytes.NewReader(b)
	default:
		encoded, err := json.Marshal(b)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		raw = encoded
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Vulnetix-CLI/1.0")
	if raw != nil && headers["Content-Type"] == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Creds != nil {
		if h := auth.GetAuthHeader(c.Creds); h != "" {
			req.Header.Set("Authorization", h)
		}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		apiErr := &Error{Status: resp.StatusCode}
		// A body that is not the error envelope still leaves the status, which
		// is more useful than discarding it because the shape surprised us.
		_ = json.Unmarshal(respBody, apiErr)
		return apiErr
	}
	if out == nil || len(respBody) == 0 {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// ContentDigest renders the RFC 9530 header for a body.
//
// The server verifies this before storing anything, which is what makes an
// upload safe to retry: a truncated transfer fails loudly instead of being
// published under a checksum asserting it arrived intact.
func ContentDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// ── Discovery ───────────────────────────────────────────────────────────────

// WellKnown is the discovery document at /.well-known/tea.
type WellKnown struct {
	SchemaVersion int `json:"schemaVersion"`
	Endpoints     []struct {
		URL      string   `json:"url"`
		Versions []string `json:"versions"`
		Priority *float64 `json:"priority,omitempty"`
	} `json:"endpoints"`
}

// Discover resolves a domain to a TEA root, following the specification: query
// DNS for the domain, fetch /.well-known/tea over HTTPS, then pick an endpoint
// and append its version.
//
// The domain may be given as a bare name, a URL, or a TEI — those are the three
// forms a person actually has to hand, and requiring them to convert between
// them would be busywork.
func Discover(ctx context.Context, domainOrTEI string) (*WellKnown, string, error) {
	domain, err := NormaliseDomain(domainOrTEI)
	if err != nil {
		return nil, "", err
	}
	wellKnownURL := "https://" + domain + "/.well-known/tea"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Vulnetix-CLI/1.0")

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, wellKnownURL, fmt.Errorf("fetch %s: %w", wellKnownURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, wellKnownURL, fmt.Errorf("%s responded %d", wellKnownURL, resp.StatusCode)
	}
	var doc WellKnown
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, wellKnownURL, fmt.Errorf("%s is not a valid discovery document: %w", wellKnownURL, err)
	}
	if doc.SchemaVersion != 1 || len(doc.Endpoints) == 0 {
		return &doc, wellKnownURL, fmt.Errorf("%s is not a schema-valid discovery document", wellKnownURL)
	}
	return &doc, wellKnownURL, nil
}

// RootFrom picks the endpoint and version to use from a discovery document.
//
// Highest priority wins, and among an endpoint's versions the newest STABLE one
// is chosen. Plain SemVer ordering would rank 1.1.0-beta.1 above 1.0.0, and
// pointing a user's tooling at a provider's beta API is not a decision to make
// on their behalf.
func RootFrom(doc *WellKnown) string {
	if doc == nil || len(doc.Endpoints) == 0 {
		return ""
	}
	best := doc.Endpoints[0]
	bestPriority := 1.0
	if best.Priority != nil {
		bestPriority = *best.Priority
	}
	for _, e := range doc.Endpoints[1:] {
		p := 1.0
		if e.Priority != nil {
			p = *e.Priority
		}
		if p > bestPriority {
			best, bestPriority = e, p
		}
	}

	stable, pre := "", ""
	for _, v := range best.Versions {
		if strings.Contains(v, "-") {
			if pre == "" {
				pre = v
			}
			continue
		}
		if stable == "" || v > stable {
			stable = v
		}
	}
	version := stable
	if version == "" {
		version = pre
	}
	if version == "" {
		return strings.TrimRight(best.URL, "/")
	}
	return strings.TrimRight(best.URL, "/") + "/v" + version
}

// NormaliseDomain reduces what a person pastes — a bare domain, a URL, or a
// TEI — to the domain-name component discovery starts from.
func NormaliseDomain(in string) (string, error) {
	s := strings.TrimSpace(in)
	if s == "" {
		return "", fmt.Errorf("a domain, URL or TEI is required")
	}
	if strings.HasPrefix(strings.ToLower(s), "urn:tei:") {
		parts := strings.Split(s, ":")
		if len(parts) < 5 {
			return "", fmt.Errorf("%q is not a well-formed TEI", in)
		}
		s = parts[3]
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return "", fmt.Errorf("%q could not be parsed as a URL", in)
		}
		s = u.Host
	}
	s = strings.ToLower(strings.Trim(strings.TrimSpace(s), "/"))
	if i := strings.LastIndex(s, ":"); i > 0 && !strings.Contains(s[i+1:], "]") {
		if port := s[i+1:]; port != "" && strings.IndexFunc(port, func(r rune) bool { return r < '0' || r > '9' }) < 0 {
			s = s[:i]
		}
	}
	if s == "" || strings.ContainsAny(s, "/?#@ ") || !strings.Contains(s, ".") {
		return "", fmt.Errorf("%q is not a domain name", in)
	}
	return s, nil
}
