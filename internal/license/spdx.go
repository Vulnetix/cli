package license

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
)

//go:embed spdx_licenses.json
var spdxJSON []byte

// spdxEntry mirrors the JSON structure per license in spdx_licenses.json.
type spdxEntry struct {
	Name          string `json:"name"`
	IsOsiApproved bool   `json:"isOsiApproved"`
	IsFsfLibre    bool   `json:"isFsfLibre"`
	IsDeprecated  bool   `json:"isDeprecatedLicenseId"`
}

var (
	spdxOnce sync.Once
	spdxDB   map[string]LicenseRecord // keyed by SPDX ID (case-preserving)
	spdxLow  map[string]string        // lowercase SPDX ID → canonical SPDX ID
)

func loadSPDX() {
	spdxOnce.Do(func() {
		var raw map[string]spdxEntry
		if err := json.Unmarshal(spdxJSON, &raw); err != nil {
			spdxDB = map[string]LicenseRecord{}
			spdxLow = map[string]string{}
			return
		}
		spdxDB = make(map[string]LicenseRecord, len(raw))
		spdxLow = make(map[string]string, len(raw))
		for id, e := range raw {
			spdxDB[id] = LicenseRecord{
				SpdxID:        id,
				Name:          e.Name,
				Category:      ClassifyCategory(id),
				IsOsiApproved: e.IsOsiApproved,
				IsFsfLibre:    e.IsFsfLibre,
				IsDeprecated:  e.IsDeprecated,
			}
			spdxLow[strings.ToLower(id)] = id
		}
	})
}

// LookupSPDX returns the license record for the given SPDX ID, or nil if not found.
// Lookup is case-insensitive.
func LookupSPDX(id string) *LicenseRecord {
	loadSPDX()
	canonical, ok := spdxLow[strings.ToLower(id)]
	if !ok {
		return nil
	}
	rec := spdxDB[canonical]
	return &rec
}

// NormalizeSPDX returns the canonical SPDX ID for a case-insensitive input,
// or the input unchanged if not found in the database.
func NormalizeSPDX(id string) string {
	loadSPDX()
	if canonical, ok := spdxLow[strings.ToLower(id)]; ok {
		return canonical
	}
	return id
}

// AllLicenses returns the full embedded SPDX license database.
func AllLicenses() map[string]LicenseRecord {
	loadSPDX()
	return spdxDB
}

// ParseSPDXExpression splits a simple SPDX license expression into constituent IDs.
// Handles "MIT", "MIT OR Apache-2.0", "GPL-2.0-only WITH Classpath-exception-2.0",
// and parenthesised groups. WITH exceptions are stripped.
func ParseSPDXExpression(expr string) []string {
	if expr == "" {
		return nil
	}
	// Remove parentheses.
	expr = strings.NewReplacer("(", " ", ")", " ").Replace(expr)
	tokens := strings.Fields(expr)

	var ids []string
	skipNext := false
	for _, tok := range tokens {
		upper := strings.ToUpper(tok)
		if upper == "OR" || upper == "AND" {
			continue
		}
		if upper == "WITH" {
			skipNext = true
			continue
		}
		if skipNext {
			skipNext = false
			continue
		}
		ids = append(ids, NormalizeSPDX(tok))
	}
	return ids
}
