package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ── CIRCL Hashlookup types ──────────────────────────────────────────────

// HashlookupResult carries the CIRCL hashlookup response for one SHA-1 hash.
//
// CIRCL returns NSRL-style PascalCase keys with hyphens ("SHA-1", "SHA-256",
// "MD5", "FileName", ...) — the json tags below mirror that exactly so the
// response unmarshals. PackageName/PackageVersion are NOT top-level CIRCL
// fields (they live in parents[] on the single-lookup endpoint, and are
// absent from the slim bulk response); they are derived in BulkHashlookup.
type HashlookupResult struct {
	FileName        string             `json:"FileName,omitempty"`
	FileSize        string             `json:"FileSize,omitempty"`
	MD5             string             `json:"MD5,omitempty"`
	SHA1            string             `json:"SHA-1,omitempty"`
	SHA256          string             `json:"SHA-256,omitempty"`
	SHA512          string             `json:"SHA-512,omitempty"`
	SSDEEP          string             `json:"SSDEEP,omitempty"`
	TLSH            string             `json:"TLSH,omitempty"`
	InsertTimestamp string             `json:"insert-timestamp,omitempty"`
	Source          string             `json:"source,omitempty"`
	PackageName     string             `json:"-"`
	PackageVersion  string             `json:"-"`
	Parents         []HashlookupParent `json:"parents,omitempty"`
}

// HashlookupParent is one parent entry from CIRCL (a known package that
// ships this binary). Only present on the single-lookup endpoint.
type HashlookupParent struct {
	SHA1               string `json:"SHA-1,omitempty"`
	SHA256             string `json:"SHA-256,omitempty"`
	MD5                string `json:"MD5,omitempty"`
	PackageName        string `json:"PackageName,omitempty"`
	PackageVersion     string `json:"PackageVersion,omitempty"`
	PackageRelease     string `json:"PackageRelease,omitempty"`
	PackageArch        string `json:"PackageArch,omitempty"`
	PackageDescription string `json:"PackageDescription,omitempty"`
}

const hashlookupBulkURL = "https://hashlookup.circl.lu/bulk/sha1"

// BulkHashlookup sends a batch of SHA-1 hashes to the CIRCL hashlookup API
// and returns results keyed by SHA-1 hex string. Errors are non-fatal —
// partial results are returned alongside any error.
func BulkHashlookup(ctx context.Context, sha1s []string) (map[string]*HashlookupResult, error) {
	if len(sha1s) == 0 {
		return nil, nil
	}

	results := make(map[string]*HashlookupResult, len(sha1s))

	// CIRCL expects: {"hashes": ["sha1hash1", "sha1hash2", ...]}
	payload, err := json.Marshal(map[string][]string{"hashes": sha1s})
	if err != nil {
		return nil, fmt.Errorf("marshal sha1 list: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "POST", hashlookupBulkURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return results, fmt.Errorf("hashlookup request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return results, fmt.Errorf("hashlookup read body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return results, fmt.Errorf("hashlookup returned %d: %s", resp.StatusCode, string(body[:min(len(body), 200)]))
	}

	// The bulk endpoint returns a JSON array of NSRL-style records; hashes
	// not present in CIRCL are simply omitted (so the array is shorter than
	// the request, or empty). Each record carries its own "SHA-1" field.
	var records []HashlookupResult
	if err := json.Unmarshal(body, &records); err != nil {
		return results, fmt.Errorf("hashlookup parse: %w", err)
	}

	for i := range records {
		r := records[i]
		// CIRCL returns SHA-1 in uppercase hex; our locally-computed hashes
		// are lowercase. Normalise the map key (and stored value) so callers
		// can look up by their own lowercase SHA-1.
		key := strings.ToLower(r.SHA1)
		if key == "" {
			continue
		}
		r.SHA1 = key

		// Populate PackageName/Version from the first parent that has them
		// (single-lookup shape); the slim bulk response has no parents.
		if r.PackageName == "" {
			for _, p := range r.Parents {
				if p.PackageName != "" {
					r.PackageName = p.PackageName
					r.PackageVersion = p.PackageVersion
					break
				}
			}
		}
		// Fallback: pop last segment of FileName as package name.
		if r.PackageName == "" && r.FileName != "" {
			r.PackageName = lastPathSegment(r.FileName)
		}

		rc := r
		results[key] = &rc
	}

	return results, nil
}

// lastPathSegment returns the last element of a path (e.g. "/usr/bin/openssl" → "openssl").
func lastPathSegment(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}

// min returns the smaller of two ints.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
