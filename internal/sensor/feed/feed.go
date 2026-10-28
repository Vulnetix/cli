// Package feed loads the runtime sensor's rules from an organisation's
// published detection rule feed (vdb-site detection_rule_feeds_sensor.go).
//
// A feed is a manifest.json listing each file with its SHA-256, the files, and
// manifest.json.sig, an Ed25519 signature over the manifest bytes. The sensor
// reads rules.json, which names each rule, its start mode and its body.
//
// Verification decides what the sensor may do with a rule, not whether it
// loads: a feed whose signature checks out against the pinned key yields
// verified rules, which may block; anything else yields unverified rules,
// which the verdict engine only ever reports. A file whose hash does not match
// the manifest is refused outright, signed or not, because it is not the file
// the manifest describes.
package feed

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	manifestName = "manifest.json"
	rulesName    = "rules.json"
	maxManifest  = 1 << 20
	maxRules     = 64 << 20
)

// Rule is one entry of rules.json.
type Rule struct {
	RuleTable  string `json:"ruleTable"`
	RuleUUID   string `json:"ruleUuid"`
	RuleType   string `json:"ruleType"`
	Name       string `json:"name"`
	CVE        string `json:"cve,omitempty"`
	DeployMode string `json:"deployMode"`
	Disabled   bool   `json:"disabled"`
	Body       string `json:"body"`
}

type manifest struct {
	FeedUUID string `json:"feedUuid"`
	FeedType string `json:"feedType"`
	Files    []struct {
		Filename string `json:"filename"`
		URL      string `json:"url"`
		SHA256   string `json:"sha256"`
	} `json:"files"`
}

// Loaded is one fetch's result.
type Loaded struct {
	FeedUUID string
	FeedType string
	Rules    []Rule
	Verified bool
	// Why the feed is not verified, in one phrase, when it is not.
	Unverified string
	ETag       string
}

// Source is one feed the sensor subscribes to.
type Source struct {
	// BaseURL is the feed's publicBaseUrl.
	BaseURL string
	// PublicKey is the pinned key. Nil means every rule loads unverified.
	PublicKey ed25519.PublicKey
	HTTP      *http.Client

	etag string
}

// ErrNotModified is returned when the manifest has not changed since the
// last successful fetch.
var ErrNotModified = errors.New("feed not modified")

// Fetch reads the feed. It returns ErrNotModified when the manifest's ETag is
// unchanged, so a poll costs one conditional request.
func (s *Source) Fetch(ctx context.Context) (Loaded, error) {
	base, err := checkBase(s.BaseURL)
	if err != nil {
		return Loaded{}, err
	}
	client := s.HTTP
	if client == nil {
		client = http.DefaultClient
	}

	manifestBytes, etag, err := get(ctx, client, base+"/"+manifestName, s.etag, maxManifest)
	if err != nil {
		return Loaded{}, err
	}
	var m manifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return Loaded{}, fmt.Errorf("manifest: %w", err)
	}

	var rulesHash string
	for _, f := range m.Files {
		if f.Filename == rulesName {
			rulesHash = strings.ToLower(f.SHA256)
		}
	}
	if rulesHash == "" {
		return Loaded{}, fmt.Errorf("the feed publishes no %s; republish it from the console", rulesName)
	}
	rulesBytes, _, err := get(ctx, client, base+"/"+rulesName, "", maxRules)
	if err != nil {
		return Loaded{}, err
	}
	sum := sha256.Sum256(rulesBytes)
	if hex.EncodeToString(sum[:]) != rulesHash {
		return Loaded{}, fmt.Errorf("%s does not match the hash in the manifest", rulesName)
	}

	var doc struct {
		Rules []Rule `json:"rules"`
	}
	if err := json.Unmarshal(rulesBytes, &doc); err != nil {
		return Loaded{}, fmt.Errorf("%s: %w", rulesName, err)
	}

	out := Loaded{FeedUUID: m.FeedUUID, FeedType: m.FeedType, Rules: doc.Rules, ETag: etag}
	out.Verified, out.Unverified = s.verify(ctx, client, base, manifestBytes)
	s.etag = etag

	return out, nil
}

func (s *Source) verify(ctx context.Context, client *http.Client, base string, manifestBytes []byte) (bool, string) {
	if len(s.PublicKey) != ed25519.PublicKeySize {
		return false, "no feed key pinned"
	}
	sigText, _, err := get(ctx, client, base+"/"+manifestName+".sig", "", 4096)
	if err != nil {
		return false, "feed is not signed"
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigText)))
	if err != nil {
		return false, "signature is not base64"
	}
	if !ed25519.Verify(s.PublicKey, manifestBytes, sig) {
		return false, "signature does not match the pinned key"
	}

	return true, ""
}

// ParsePublicKey reads a pinned key: base64 of the 32 raw bytes.
func ParsePublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("feed key is not base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("feed key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}

	return ed25519.PublicKey(raw), nil
}

// checkBase refuses anything but https, except loopback for tests and local
// mirrors: a rule set fetched over plain http from elsewhere can be swapped in
// transit, and the hash check alone cannot catch a swapped manifest.
func checkBase(raw string) (string, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(raw), "/"))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("feed URL %q is not a URL", raw)
	}
	host := u.Hostname()
	loopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
		return "", fmt.Errorf("feed URL must be https")
	}

	return u.String(), nil
}

func get(ctx context.Context, client *http.Client, target, etag string, limit int64) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, "", err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotModified {
		return nil, etag, ErrNotModified
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("GET %s: HTTP %d", target, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(body)) > limit {
		return nil, "", fmt.Errorf("GET %s: larger than %d bytes", target, limit)
	}

	return body, resp.Header.Get("ETag"), nil
}
