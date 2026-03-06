package update

import (
	"fmt"
	"strconv"
	"strings"
)

// Version represents a parsed semantic version.
type Version struct {
	Major      int
	Minor      int
	Patch      int
	PreRelease string // e.g. "dev", "rc1"
}

// ParseVersion parses a version string like "1.2.3", "v1.2.3", or "1.2.3-dev".
func ParseVersion(s string) (Version, error) {
	s = strings.TrimPrefix(s, "v")

	var v Version

	// Split off pre-release suffix
	if idx := strings.IndexByte(s, '-'); idx != -1 {
		v.PreRelease = s[idx+1:]
		s = s[:idx]
	}

	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, fmt.Errorf("invalid version format: %q", s)
	}

	var err error
	v.Major, err = strconv.Atoi(parts[0])
	if err != nil {
		return v, fmt.Errorf("invalid major version: %q", parts[0])
	}
	v.Minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return v, fmt.Errorf("invalid minor version: %q", parts[1])
	}
	v.Patch, err = strconv.Atoi(parts[2])
	if err != nil {
		return v, fmt.Errorf("invalid patch version: %q", parts[2])
	}

	return v, nil
}

// String returns the version as "X.Y.Z" or "X.Y.Z-pre".
func (v Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.PreRelease != "" {
		s += "-" + v.PreRelease
	}
	return s
}

// Compare returns -1, 0, or 1 comparing v to other.
// Pre-release versions are considered older than the same version without pre-release.
func (v Version) Compare(other Version) int {
	if v.Major != other.Major {
		return cmpInt(v.Major, other.Major)
	}
	if v.Minor != other.Minor {
		return cmpInt(v.Minor, other.Minor)
	}
	if v.Patch != other.Patch {
		return cmpInt(v.Patch, other.Patch)
	}

	// Both have no pre-release: equal
	if v.PreRelease == "" && other.PreRelease == "" {
		return 0
	}
	// Pre-release < release
	if v.PreRelease != "" && other.PreRelease == "" {
		return -1
	}
	if v.PreRelease == "" && other.PreRelease != "" {
		return 1
	}
	// Both have pre-release: lexicographic
	return strings.Compare(v.PreRelease, other.PreRelease)
}

// IsNewerThan returns true if v is strictly newer than other.
func (v Version) IsNewerThan(other Version) bool {
	return v.Compare(other) > 0
}

func cmpInt(a, b int) int {
	if a < b {
		return -1
	}
	return 1
}
