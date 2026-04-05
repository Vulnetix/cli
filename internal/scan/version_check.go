package scan

import (
	"strings"

	"github.com/vulnetix/cli/internal/update"
)

// IsVersionAffected checks whether installedVersion falls within the affected
// version range string returned by the VDB API.
//
// Supported range formats:
//
//	">= 2.0.0, < 2.3.1"     comma-separated constraints
//	"[2.0.0, 2.3.1)"         interval notation
//	"< 3.0.0"                single constraint
//	"2.3.1"                  exact version match
//
// Returns true if the installed version IS affected.
// When parsing fails the function returns true (assume affected) to err on
// the side of caution.
func IsVersionAffected(installedVersion, versionRange, ecosystem string) bool {
	if versionRange == "" {
		return true // no range data — assume affected
	}

	installed, err := update.ParseVersion(strings.TrimPrefix(installedVersion, "v"))
	if err != nil {
		return true // can't parse installed version — assume affected
	}

	// Normalise: strip leading/trailing whitespace, brackets.
	vr := strings.TrimSpace(versionRange)

	// Interval notation: [X, Y) or (X, Y]
	if (strings.HasPrefix(vr, "[") || strings.HasPrefix(vr, "(")) &&
		(strings.HasSuffix(vr, "]") || strings.HasSuffix(vr, ")")) {
		return checkInterval(installed, vr)
	}

	// Comma-separated constraints: ">= 2.0, < 3.0"
	parts := strings.Split(vr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !matchConstraint(installed, part) {
			return false
		}
	}
	return true
}

// checkInterval parses interval notation like "[2.0.0, 2.3.1)" and checks
// whether ver falls within.
func checkInterval(ver update.Version, interval string) bool {
	lowerInclusive := interval[0] == '['
	upperInclusive := interval[len(interval)-1] == ']'

	inner := interval[1 : len(interval)-1]
	parts := strings.SplitN(inner, ",", 2)
	if len(parts) != 2 {
		return true // can't parse — assume affected
	}

	lowerStr := strings.TrimSpace(parts[0])
	upperStr := strings.TrimSpace(parts[1])

	lower, errL := update.ParseVersion(strings.TrimPrefix(lowerStr, "v"))
	upper, errU := update.ParseVersion(strings.TrimPrefix(upperStr, "v"))

	if errL != nil || errU != nil {
		return true
	}

	cmpLower := ver.Compare(lower)
	cmpUpper := ver.Compare(upper)

	lowerOK := cmpLower > 0 || (lowerInclusive && cmpLower == 0)
	upperOK := cmpUpper < 0 || (upperInclusive && cmpUpper == 0)

	return lowerOK && upperOK
}

// matchConstraint evaluates a single constraint like ">= 2.0.0" or "< 3.0.0"
// against ver. Returns true if the constraint is satisfied (i.e. version is
// within the affected range).
func matchConstraint(ver update.Version, constraint string) bool {
	constraint = strings.TrimSpace(constraint)

	// Detect operator prefix.
	var op string
	var verStr string

	for _, prefix := range []string{">=", "<=", "!=", ">", "<", "="} {
		if strings.HasPrefix(constraint, prefix) {
			op = prefix
			verStr = strings.TrimSpace(constraint[len(prefix):])
			break
		}
	}
	if op == "" {
		// No operator — treat as exact version match.
		verStr = constraint
		op = "="
	}

	target, err := update.ParseVersion(strings.TrimPrefix(verStr, "v"))
	if err != nil {
		return true // can't parse — assume affected
	}

	cmp := ver.Compare(target)

	switch op {
	case ">=":
		return cmp >= 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case "<":
		return cmp < 0
	case "=":
		return cmp == 0
	case "!=":
		return cmp != 0
	default:
		return true
	}
}
