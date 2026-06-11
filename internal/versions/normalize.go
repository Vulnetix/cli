// Package versions provides SemVer-aware version parsing, comparison, range
// evaluation, and CVE 5.1 affected/unaffected status determination.
//
// MIRRORED — this package is kept byte-identical between
// vdb-api/internal/versions and cli/internal/versions. The shared test
// corpus lives in corpus_test.go. Update both copies together.
package versions

import "strings"

// unicodeOps maps unicode comparison operators (seen in upstream advisory
// text) to their ASCII equivalents.
var unicodeOps = strings.NewReplacer(
	"≥", ">=",
	"≤", "<=",
	"≠", "!=",
	"＜", "<",
	"＞", ">",
	"＝", "=",
	"．", ".",
)

// Normalize prepares a raw version (or range fragment) string for parsing:
// unicode operators become ASCII, whitespace is trimmed and collapsed, and
// the redundant "v"/"V" and "npm:" prefixes are stripped from version tokens.
func Normalize(s string) string {
	s = unicodeOps.Replace(s)
	s = strings.Join(strings.Fields(s), " ")
	s = strings.TrimPrefix(s, "npm:")
	s = stripVPrefix(s)
	return s
}

// stripVPrefix removes a leading "v"/"V" only when it prefixes a digit, so
// product names like "vault" survive untouched.
func stripVPrefix(s string) string {
	if len(s) >= 2 && (s[0] == 'v' || s[0] == 'V') && s[1] >= '0' && s[1] <= '9' {
		return s[1:]
	}
	return s
}

// normalizeRangeString prepares a whole range expression: unicode operators
// to ASCII and whitespace collapsed. Version-token prefixes are handled
// per-token during parsing, not here.
func normalizeRangeString(s string) string {
	s = unicodeOps.Replace(s)
	return strings.Join(strings.Fields(s), " ")
}

// NormalizeStatus maps the status vocabulary seen across CVE 5.1, MSRC, and
// relationship-type data onto the canonical three-state Status.
func NormalizeStatus(s string) Status {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "affected", "known_affected", "vulnerable", "affects":
		return StatusAffected
	case "unaffected", "known_not_affected", "not_affected":
		return StatusUnaffected
	default:
		return StatusUnknown
	}
}
