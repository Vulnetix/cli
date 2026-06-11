package scan

import (
	"github.com/vulnetix/cli/v3/internal/versions"
)

// IsVersionAffected checks whether installedVersion falls within the affected
// version range string returned by the VDB API.
//
// Supported range formats (full grammar in internal/versions):
//
//	">= 2.0.0, < 2.3.1"      comma-separated AND constraints
//	"1.14.1, 0.30.4"         bare comma list — OR exact matches
//	"[2.0.0, 2.3.1)"         interval notation
//	"< 3.0.0"                single constraint
//	">= 1.0.0 < 2.0.0"       space-separated AND constraints
//	"< 2.11.2 || = 3.0.1"    "||"-separated OR ranges
//	"≥ 0.31.0 < 1.2.0"       unicode operators
//	"2.3.1"                  exact version match
//	"*"                      all versions
//
// Returns true if the installed version IS affected.
// When parsing fails the function returns true (assume affected) to err on
// the side of caution.
func IsVersionAffected(installedVersion, versionRange, ecosystem string) bool {
	if versionRange == "" {
		return true // no range data — assume affected
	}

	installed, err := versions.Parse(installedVersion)
	if err != nil {
		return true // can't parse installed version — assume affected
	}

	rs, err := versions.ParseRange(versionRange)
	if err != nil {
		return true // can't parse range — assume affected
	}

	policy := versions.ResolvePseudoPolicy(versions.Options{Ecosystem: ecosystem})
	return rs.Contains(installed, policy)
}
