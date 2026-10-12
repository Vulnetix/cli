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
	"regexp"
	"strings"
	"time"

	"github.com/vulnetix/cli/v3/pkg/auth"
)

// DefaultServer is Vulnetix's own TEA root, at the current specification. It is
// the base advertised in https://vulnetix.com/.well-known/tea completed with
// "/v1.0.0", which is exactly how that document tells a client to build it.
const DefaultServer = "https://www.vulnetix.com/tea/v1.0.0"

// PublicServer is the open source catalogue root: the top GitHub projects by
// stars, published as products and components. It is a different root from
// DefaultServer, not a filtered view of it. It requires a credential but has no
// plan gate, so any valid ApiKey, including the shared community one, reads it.
const PublicServer = "https://www.vulnetix.com/tea/public/v1.0.0"

// LegacyServer and LegacyPublicServer are the same two roots at TEA 0.4.0, for a
// caller that has to read the older shapes: `--server` takes either.
const (
	LegacyServer       = "https://www.vulnetix.com/tea/v0.4.0"
	LegacyPublicServer = "https://www.vulnetix.com/tea/public/v0.4.0"
)

// stableAlias is where the publication operations are served. Publication is a
// Vulnetix extension and not part of any TEA version, so it is not at the version
// path; it is at the stable alias, which is also what publishers have always
// written to.
var stableAliasRE = regexp.MustCompile(`^(.*/tea)/v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$`)

// PublicationBase maps a server root to where the publication operations live.
// For a Vulnetix-shaped root (".../tea/v<version>") that is ".../tea/v1"; any
// other root is returned as it is, because publication is Vulnetix's extension
// and a server that has it serves it where it serves everything else.
func PublicationBase(root string) string {
	root = strings.TrimRight(strings.TrimSpace(root), "/")
	if m := stableAliasRE.FindStringSubmatch(root); m != nil {
		return m[1] + "/v1"
	}
	return root
}

// Catalogue names accepted by ServerForCatalogue.
const (
	CatalogueFirstParty = "first-party"
	CataloguePublic     = "public"
)

// Catalogues lists the valid catalogue names, default first.
var Catalogues = []string{CatalogueFirstParty, CataloguePublic}

// ServerForCatalogue maps a catalogue name to its root URL. An empty name is
// the first party catalogue. Matching ignores case and surrounding space.
func ServerForCatalogue(name string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", CatalogueFirstParty:
		return DefaultServer, nil
	case CataloguePublic:
		return PublicServer, nil
	}
	return "", fmt.Errorf("unknown catalogue %q: valid catalogues are %s",
		name, strings.Join(Catalogues, ", "))
}

// IsPublicServer reports whether a root URL is the open source catalogue root,
// ignoring a trailing slash and letter case.
func IsPublicServer(root string) bool {
	root = strings.TrimRight(strings.TrimSpace(root), "/")
	for _, public := range []string{PublicServer, LegacyPublicServer, "https://www.vulnetix.com/tea/public/v1"} {
		if strings.EqualFold(root, public) {
			return true
		}
	}
	return false
}

// Client talks to one TEA server.
type Client struct {
	BaseURL string

	// PublishURL is where the publication operations are sent. Left empty it is
	// worked out from BaseURL (see PublicationBase), which is right unless a caller
	// is pointing at a server that serves publication somewhere unusual.
	PublishURL string
	Creds      *auth.Credentials
	HTTP       *http.Client

	// Err, when set, is returned by every request instead of sending it. It lets
	// a caller that could not configure the client (conflicting flags, say)
	// hand back a client that fails loudly rather than one that quietly talks
	// to the wrong server.
	Err error
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

// IsNotImplemented reports a 1.0.0 server saying it does not provide an optional
// capability (CLE, /token). It is not a failure of the object: a client carries on
// without the capability.
func (e *Error) IsNotImplemented() bool { return e.Code == "NOT_IMPLEMENTED" }

// IsInvalidPageToken reports a 1.0.0 server refusing a page token, because it was
// not issued for this request or a parameter now contradicts it. The remedy is to
// start the listing again without the token.
func (e *Error) IsInvalidPageToken() bool { return e.Code == "INVALID_PAGE_TOKEN" }

// IsSignatureNotFound reports a 1.0.0 server saying the artifact exists and has no
// signature for the format asked about.
func (e *Error) IsSignatureNotFound() bool { return e.Code == "SIGNATURE_NOT_FOUND" }

// IsNoAcceptableFormat reports a 1.0.0 server saying the artifact has no format
// matching the request.
func (e *Error) IsNoAcceptableFormat() bool { return e.Code == "NO_ACCEPTABLE_FORMAT" }

// Version is the TEA specification version the client's root names, normalised to
// major.minor.patch, or "" when the root does not say. The stable alias /tea/v1
// and a custom path do not, which is why a caller cannot assume one.
func (c *Client) Version() string { return VersionFromRoot(c.BaseURL) }

// publishBase is where the publication operations are sent.
func (c *Client) publishBase() string {
	if strings.TrimSpace(c.PublishURL) != "" {
		return strings.TrimRight(c.PublishURL, "/")
	}
	return PublicationBase(c.BaseURL)
}

// Do performs one request against the server's TEA root and decodes the result
// into out.
//
// headers are applied last so a caller can set Idempotency-Key and
// Content-Digest, which are the two the publication API acts on and which a
// generic client would otherwise have no way to send.
func (c *Client) Do(ctx context.Context, method, path string, body any, out any, headers map[string]string) error {
	return c.do(ctx, c.BaseURL, method, path, body, out, headers)
}

// DoPublish is Do for the publication operations, which are not served at the
// version path (see PublicationBase).
func (c *Client) DoPublish(ctx context.Context, method, path string, body any, out any, headers map[string]string) error {
	return c.do(ctx, c.publishBase(), method, path, body, out, headers)
}

func (c *Client) do(ctx context.Context, base, method, path string, body any, out any, headers map[string]string) error {
	if c.Err != nil {
		return c.Err
	}
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

	req, err := http.NewRequestWithContext(ctx, method, base+path, reader)
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
	SchemaVersion int                 `json:"schemaVersion"`
	Endpoints     []WellKnownEndpoint `json:"endpoints"`
}

// WellKnownEndpoint is one entry of the discovery document's endpoints.
type WellKnownEndpoint struct {
	URL      string   `json:"url"`
	Versions []string `json:"versions"`
	Priority *float64 `json:"priority,omitempty"`
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

// RootsFrom lists every root worth trying for a discovery document, best first
// (see RankCandidates for the rules). A caller fails over down the list on DNS
// or TLS errors, 5xx, and a 404 that carries no TEA error body, but not on 401
// or 403.
func RootsFrom(doc *WellKnown) []string {
	cands := RankCandidates(doc, SupportedVersions)
	out := make([]string, len(cands))
	for i, c := range cands {
		out[i] = c.Root()
	}
	return out
}

// RootFrom is the best root for a discovery document, or "" when the provider
// offers no version this client speaks.
func RootFrom(doc *WellKnown) string {
	if roots := RootsFrom(doc); len(roots) > 0 {
		return roots[0]
	}
	return ""
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
