package versions

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Status is the canonical three-state outcome of a version evaluation.
type Status string

const (
	StatusAffected   Status = "affected"
	StatusUnaffected Status = "unaffected"
	StatusUnknown    Status = "unknown"
)

// PseudoPolicy controls whether a pseudo/build-suffixed version (e.g.
// "5.3.2-0.20260526213025-e8e5b83ca9a5") is considered equal to its base
// release ("5.3.2") for exact-match (= / !=) purposes. Relational operators
// always use true SemVer ordering regardless of policy.
type PseudoPolicy int

const (
	// PseudoBaseEqual treats the suffix as a build artifact: the pseudo
	// version equals its base release for exact matches. Default for
	// ecosystems other than Go.
	PseudoBaseEqual PseudoPolicy = iota
	// PseudoStrict follows Go module semantics: a pseudo-version sorts
	// strictly before its base release and never equals it. Default for
	// the go/golang ecosystem.
	PseudoStrict
)

// Options threads ecosystem context (and an optional explicit policy
// override) through evaluation call sites.
type Options struct {
	Ecosystem    string
	PseudoPolicy *PseudoPolicy
}

// ResolvePseudoPolicy returns the effective policy: an explicit override
// wins; otherwise the go/golang ecosystem gets PseudoStrict and everything
// else gets PseudoBaseEqual.
func ResolvePseudoPolicy(opt Options) PseudoPolicy {
	if opt.PseudoPolicy != nil {
		return *opt.PseudoPolicy
	}
	switch strings.ToLower(strings.TrimSpace(opt.Ecosystem)) {
	case "go", "golang", "gomod", "go-modules", "golang-proxy":
		return PseudoStrict
	}
	return PseudoBaseEqual
}

// Version is a parsed, comparison-ready version.
type Version struct {
	Major, Minor, Patch uint64
	Extra               []uint64 // 4th+ numeric segments (maven/.NET style), compared after Patch
	Prerelease          string
	PrereleaseIDs       []string // dot-split identifiers for SemVer 2.0 precedence
	Build               string   // build metadata after "+", ignored in comparison
	IsPseudo            bool     // timestamp+hash suffix detected (Go pseudo-version or distro rebuild)
	PseudoBase          string   // e.g. "5.3.2"
	PseudoTimestamp     string   // e.g. "20260526213025"
	Wildcard            bool     // "*" or "x" — equals anything
	SegWildcard         bool     // a SEGMENT is a wildcard ("8.x", "1.2.*") — prefix-matches for =/!=
	SegWildcardAt       int      // index of the first wildcard segment (0=major)
	Original            string
}

// pseudoRe matches a prerelease that ends with a 14-digit timestamp and a
// hex hash: "20220622213112-05595931fe9d", "0.20260526213025-e8e5b83ca9a5",
// "beta.0.20240101000000-abcdef123456".
var pseudoRe = regexp.MustCompile(`(?:^|\.)(\d{14})-([0-9a-fA-F]{7,40})$`)

// Parse parses a version string tolerantly: optional v/V and npm: prefixes,
// unicode digits/operators normalized, 1–4+ numeric segments ("1.2" →
// 1.2.0), wildcard segments ("1.2.x" → 1.2.0), prerelease and build
// metadata, full-string wildcards ("*", "x"), and Go-style pseudo-versions.
func Parse(s string) (Version, error) {
	v := Version{Original: s}
	s = Normalize(s)
	if s == "" {
		return v, fmt.Errorf("empty version")
	}
	if s == "*" || s == "x" || s == "X" {
		v.Wildcard = true
		return v, nil
	}

	// Build metadata: everything after the first "+" is ignored for
	// comparison but preserved.
	if i := strings.IndexByte(s, '+'); i >= 0 {
		v.Build = s[i+1:]
		s = s[:i]
	}
	// Prerelease: everything after the first "-".
	if i := strings.IndexByte(s, '-'); i >= 0 {
		v.Prerelease = s[i+1:]
		s = s[:i]
	}
	if s == "" {
		return v, fmt.Errorf("missing version core in %q", v.Original)
	}

	parts := strings.Split(s, ".")
	nums := make([]uint64, 0, len(parts))
	for i, p := range parts {
		if p == "x" || p == "X" || p == "*" {
			if !v.SegWildcard {
				v.SegWildcard = true
				v.SegWildcardAt = i
			}
			nums = append(nums, 0)
			continue
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return v, fmt.Errorf("invalid version segment %q in %q", p, v.Original)
		}
		nums = append(nums, n)
	}
	switch {
	case len(nums) >= 3:
		v.Major, v.Minor, v.Patch = nums[0], nums[1], nums[2]
		v.Extra = nums[3:]
	case len(nums) == 2:
		v.Major, v.Minor = nums[0], nums[1]
	case len(nums) == 1:
		v.Major = nums[0]
	}

	if v.Prerelease != "" {
		v.PrereleaseIDs = strings.Split(v.Prerelease, ".")
		if m := pseudoRe.FindStringSubmatch(v.Prerelease); m != nil {
			v.IsPseudo = true
			v.PseudoTimestamp = m[1]
			v.PseudoBase = fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
		}
	}

	return v, nil
}

// Compare returns -1, 0, or 1 ordering a against b per SemVer 2.0 precedence
// (extended with Extra segments for 4-part schemes). Build metadata is
// ignored. A Wildcard version compares equal to anything.
func Compare(a, b Version) int {
	if a.Wildcard || b.Wildcard {
		return 0
	}
	if c := cmpUint(a.Major, b.Major); c != 0 {
		return c
	}
	if c := cmpUint(a.Minor, b.Minor); c != 0 {
		return c
	}
	if c := cmpUint(a.Patch, b.Patch); c != 0 {
		return c
	}
	for i := range max(len(a.Extra), len(b.Extra)) {
		var ae, be uint64
		if i < len(a.Extra) {
			ae = a.Extra[i]
		}
		if i < len(b.Extra) {
			be = b.Extra[i]
		}
		if c := cmpUint(ae, be); c != 0 {
			return c
		}
	}
	return comparePrerelease(a, b)
}

// comparePrerelease implements SemVer 2.0 §11: a prerelease sorts before the
// release; identifiers compare dot-by-dot, numeric identifiers numerically
// and below alphanumeric ones, and a shorter identifier list sorts first.
func comparePrerelease(a, b Version) int {
	if a.Prerelease == "" && b.Prerelease == "" {
		return 0
	}
	if a.Prerelease == "" {
		return 1
	}
	if b.Prerelease == "" {
		return -1
	}
	for i := 0; i < len(a.PrereleaseIDs) || i < len(b.PrereleaseIDs); i++ {
		if i >= len(a.PrereleaseIDs) {
			return -1
		}
		if i >= len(b.PrereleaseIDs) {
			return 1
		}
		ai, bi := a.PrereleaseIDs[i], b.PrereleaseIDs[i]
		an, aNum := parseNumericID(ai)
		bn, bNum := parseNumericID(bi)
		switch {
		case aNum && bNum:
			if c := cmpUint(an, bn); c != 0 {
				return c
			}
		case aNum:
			return -1
		case bNum:
			return 1
		default:
			if c := strings.Compare(ai, bi); c != 0 {
				return c
			}
		}
	}
	return 0
}

// EqualExact reports whether a and b match for "="/"!=" purposes. Under
// PseudoBaseEqual a pseudo/build-suffixed version additionally equals its
// bare base release (in either direction). Wildcards equal anything; a
// segment wildcard ("8.x") prefix-matches any version sharing the segments
// before it ("8.x" equals 8.2.0 but not 9.0.0).
func EqualExact(a, b Version, p PseudoPolicy) bool {
	if a.Wildcard || b.Wildcard {
		return true
	}
	if a.SegWildcard || b.SegWildcard {
		return segPrefixEqual(a, b)
	}
	if Compare(a, b) == 0 {
		return true
	}
	if p != PseudoBaseEqual {
		return false
	}
	if a.IsPseudo && b.Prerelease == "" && coreEqual(a, b) {
		return true
	}
	if b.IsPseudo && a.Prerelease == "" && coreEqual(a, b) {
		return true
	}
	return false
}

// segPrefixEqual compares only the numeric segments BEFORE the first
// wildcard segment of either side ("8.x" vs 8.2.0 compares major only).
// Prerelease and build metadata are ignored for wildcard matching.
func segPrefixEqual(a, b Version) bool {
	limit := 3 + max(len(a.Extra), len(b.Extra))
	if a.SegWildcard && a.SegWildcardAt < limit {
		limit = a.SegWildcardAt
	}
	if b.SegWildcard && b.SegWildcardAt < limit {
		limit = b.SegWildcardAt
	}
	seg := func(v Version, i int) uint64 {
		switch i {
		case 0:
			return v.Major
		case 1:
			return v.Minor
		case 2:
			return v.Patch
		default:
			if i-3 < len(v.Extra) {
				return v.Extra[i-3]
			}
			return 0
		}
	}
	for i := range limit {
		if seg(a, i) != seg(b, i) {
			return false
		}
	}
	return true
}

// coreEqual compares only the numeric core (Major.Minor.Patch + Extra).
func coreEqual(a, b Version) bool {
	stripped := func(v Version) Version {
		return Version{Major: v.Major, Minor: v.Minor, Patch: v.Patch, Extra: v.Extra}
	}
	return Compare(stripped(a), stripped(b)) == 0
}

func parseNumericID(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
