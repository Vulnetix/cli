package feed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// RuleTypeIOCList is the rule type of an indicator list the site serves.
const RuleTypeIOCList = "IOC_LIST"

// maxIndicators bounds an indicator list's body. The site cuts a list at
// 250,000 indicators, which is well inside this even for long URLs.
const maxIndicators = 32 << 20

// UnverifiedIndicators is why an indicator list is never verified.
const UnverifiedIndicators = "served by the site; indicator lists report and never block"

// ErrRevoked is returned when the site refused the sensor's credential as
// revoked (401 with {"revoked":true}).
var ErrRevoked = errors.New("the sensor's credential was revoked")

// IsIndicatorRef is whether ref names an indicator list the site serves:
// catalog:<id> or org:<uuid>.
func IsIndicatorRef(ref string) bool {
	_, _, ok := indicatorPath(ref)

	return ok
}

// indicatorPath splits a catalog: or org: reference into its scope and id.
func indicatorPath(ref string) (scope, id string, ok bool) {
	scope, id, found := strings.Cut(strings.TrimSpace(ref), ":")
	if !found || id == "" || strings.ContainsAny(id, "/?#") {
		return "", "", false
	}
	switch scope {
	case "catalog":
		return scope, id, true
	case "org":
		if _, err := uuid.Parse(id); err != nil {
			return "", "", false
		}

		return scope, id, true
	}

	return "", "", false
}

// IndicatorRuleUUID is the rule uuid an indicator list loads under, stable
// for the reference so the console keeps one row per feed.
func IndicatorRuleUUID(ref string) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("vulnetix-feed:"+ref)).String()
}

// Indicators is an indicator list the site serves for a catalog: or org:
// reference (GET /v1/runtime/feeds/{scope}/{id}/indicators). It loads as one
// IOC_LIST rule that is never verified: its matches report and never hold.
type Indicators struct {
	// Reference is catalog:<id> or org:<uuid>.
	Reference string
	// Endpoint is the site API the uplink talks to.
	Endpoint string
	// Authorization is the sensor's Authorization header, the uplink's.
	Authorization func() string
	// Stopped, when set and true, skips the fetch: the uplink was stopped by
	// a revoked credential, and the last list keeps running.
	Stopped   func() bool
	HTTP      *http.Client
	UserAgent string

	etag    string
	revoked bool
}

// Ref is the reference.
func (s *Indicators) Ref() string { return s.Reference }

// Fetch reads the list, with ?etag= and If-None-Match from the last good
// fetch, so an unchanged list costs a 304.
func (s *Indicators) Fetch(ctx context.Context) (Loaded, error) {
	scope, id, ok := indicatorPath(s.Reference)
	if !ok {
		return Loaded{}, fmt.Errorf("feed reference %q is not catalog:<id> or org:<uuid>", s.Reference)
	}
	if s.revoked || (s.Stopped != nil && s.Stopped()) {
		return Loaded{}, ErrRevoked
	}
	endpoint := strings.TrimRight(s.Endpoint, "/")
	if endpoint == "" {
		return Loaded{}, errors.New("no site endpoint for indicator feeds")
	}
	target := endpoint + "/v1/runtime/feeds/" + scope + "/" + url.PathEscape(id) + "/indicators"
	if s.etag != "" {
		target += "?" + url.Values{"etag": {s.etag}}.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return Loaded{}, err
	}
	if s.etag != "" {
		req.Header.Set("If-None-Match", `"`+s.etag+`"`)
	}
	req.Header.Set("Accept", "text/plain")
	if s.UserAgent != "" {
		req.Header.Set("User-Agent", s.UserAgent)
	}
	if s.Authorization != nil {
		if h := s.Authorization(); h != "" {
			req.Header.Set("Authorization", h)
		}
	}
	// No Accept-Encoding: Go's transport then asks for gzip itself and
	// decompresses transparently.
	client := s.HTTP
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	resp, err := client.Do(req)
	if err != nil {
		return Loaded{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		return Loaded{}, ErrNotModified
	case http.StatusUnauthorized:
		var msg struct {
			Revoked bool `json:"revoked"`
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if json.Unmarshal(raw, &msg) == nil && msg.Revoked {
			s.revoked = true

			return Loaded{}, ErrRevoked
		}

		return Loaded{}, fmt.Errorf("GET %s: HTTP 401", s.Reference)
	default:
		return Loaded{}, fmt.Errorf("GET %s indicators: HTTP %d", s.Reference, resp.StatusCode)
	}

	// Read straight into the string the rule keeps: one copy of the list,
	// which the engine's indicator keys then point into.
	var b strings.Builder
	if n := resp.ContentLength; n > 0 && n <= maxIndicators && resp.Header.Get("Content-Encoding") == "" {
		b.Grow(int(n))
	}
	if _, err := io.Copy(&b, io.LimitReader(resp.Body, maxIndicators+1)); err != nil {
		return Loaded{}, fmt.Errorf("GET %s indicators: %w", s.Reference, err)
	}
	if b.Len() > maxIndicators {
		return Loaded{}, fmt.Errorf("GET %s indicators: larger than %d bytes", s.Reference, maxIndicators)
	}
	body := b.String()
	etag := bareETag(resp.Header.Get("ETag"))
	if etag == "" {
		etag = headerETag(body)
	}

	out := Loaded{
		FeedType:   RuleTypeIOCList,
		Unverified: UnverifiedIndicators,
		ETag:       etag,
		Rules: []Rule{{
			RuleTable:  "ioc",
			RuleUUID:   IndicatorRuleUUID(s.Reference),
			RuleType:   RuleTypeIOCList,
			Name:       s.Reference,
			DeployMode: "log",
			Body:       body,
		}},
	}
	s.etag = etag

	return out, nil
}

// bareETag drops a weak prefix and the quotes, the form ?etag= takes.
func bareETag(h string) string {
	return strings.Trim(strings.TrimPrefix(strings.TrimSpace(h), "W/"), `"`)
}

// headerETag reads "# etag <hex>" from the list's header comments.
func headerETag(body string) string {
	for body != "" && body[0] == '#' {
		line := body
		if i := strings.IndexByte(body, '\n'); i >= 0 {
			line, body = body[:i], body[i+1:]
		} else {
			body = ""
		}
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "# etag "); ok {
			return strings.TrimSpace(v)
		}
	}

	return ""
}
