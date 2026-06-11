package versions

import (
	"fmt"
	"strings"
)

// VersionEntry mirrors a CVE 5.1 affected.versions[] element (one row of
// CVEAffectedVersion): an exact version or a range with an "introduced"
// lower bound (Version) and an exclusive (LessThan) or inclusive
// (LessThanOrEqual) upper bound.
type VersionEntry struct {
	Version         string
	Status          Status
	VersionType     string
	LessThan        *string
	LessThanOrEqual *string
	Changes         []VersionChange
}

// VersionChange is a CVE 5.1 in-range status step: at version At and above
// (within the entry's range) the status becomes Status.
type VersionChange struct {
	At     string
	Status Status
}

// Evidence explains why EvaluateStatus reached its verdict.
type Evidence struct {
	// MatchKind is one of: exact-unaffected, exact-affected,
	// range-unaffected, range-affected, default, unparseable-version, none.
	MatchKind string
	// RangeString is the canonical rendering of the deciding entry.
	RangeString string
}

// EvaluateStatus determines whether installed is affected, unaffected, or
// unknown given CVE 5.1 version entries and a default status.
//
// Precedence (first hit wins):
//  1. exact entry, status unaffected, exact match  → unaffected
//  2. exact entry, status affected, exact match    → affected
//  3. range entry, status unaffected, contains     → unaffected
//  4. range entry, status affected, contains       → affected
//  5. defaultStatus affected/unaffected            → that status
//  6. → unknown
//
// An entry's Changes array (in-range status steps) overrides the entry
// status with the status of the latest change at or below installed.
// Junk entries (unparseable versions/bounds) are skipped, never fatal.
func EvaluateStatus(installed string, entries []VersionEntry, defaultStatus string, opt Options) (Status, Evidence) {
	v, err := Parse(installed)
	if err != nil {
		return StatusUnknown, Evidence{MatchKind: "unparseable-version"}
	}
	policy := ResolvePseudoPolicy(opt)

	type rangeHit struct {
		status Status
		render string
	}
	var exactUnaffected, exactAffected *Evidence
	var rangeHits []rangeHit

	for _, e := range entries {
		status := e.Status
		if status != StatusAffected && status != StatusUnaffected && status != StatusUnknown {
			status = NormalizeStatus(string(e.Status))
		}
		lower, lowerOK := parseBound(e.Version)
		upperLt, upperLtOK := parseBoundPtr(e.LessThan)
		upperLte, upperLteOK := parseBoundPtr(e.LessThanOrEqual)
		isRange := upperLtOK || upperLteOK ||
			(e.LessThan != nil && isWildcardBound(*e.LessThan)) ||
			(e.LessThanOrEqual != nil && isWildcardBound(*e.LessThanOrEqual)) ||
			(lowerOK && lower.Wildcard)

		if !isRange {
			// Exact entry.
			if !lowerOK {
				continue // junk version string — skip
			}
			if !EqualExact(v, lower, policy) {
				continue
			}
			ev := Evidence{RangeString: "= " + renderVersion(lower)}
			switch status {
			case StatusUnaffected:
				ev.MatchKind = "exact-unaffected"
				if exactUnaffected == nil {
					exactUnaffected = &ev
				}
			case StatusAffected:
				ev.MatchKind = "exact-affected"
				if exactAffected == nil {
					exactAffected = &ev
				}
			}
			continue
		}

		// Range entry: introduced lower bound (when meaningful) + upper
		// bound. A zero lower bound ("0", "0.0.0") means unbounded below so
		// prereleases of 0.0.0 (e.g. Go pseudo-versions) are included.
		contained := true
		if lowerOK && !lower.Wildcard && !isZeroVersion(lower) {
			if Compare(v, lower) < 0 {
				contained = false
			}
		}
		if contained && upperLtOK && !upperLt.Wildcard {
			if Compare(v, upperLt) >= 0 {
				contained = false
			}
		}
		if contained && upperLteOK && !upperLte.Wildcard {
			if Compare(v, upperLte) > 0 {
				contained = false
			}
		}
		if !contained {
			continue
		}
		effective := effectiveStatus(v, status, e.Changes)
		if effective != StatusAffected && effective != StatusUnaffected {
			continue
		}
		rangeHits = append(rangeHits, rangeHit{status: effective, render: renderEntry(e)})
	}

	if exactUnaffected != nil {
		return StatusUnaffected, *exactUnaffected
	}
	if exactAffected != nil {
		return StatusAffected, *exactAffected
	}
	for _, h := range rangeHits {
		if h.status == StatusUnaffected {
			return StatusUnaffected, Evidence{MatchKind: "range-unaffected", RangeString: h.render}
		}
	}
	for _, h := range rangeHits {
		if h.status == StatusAffected {
			return StatusAffected, Evidence{MatchKind: "range-affected", RangeString: h.render}
		}
	}
	switch NormalizeStatus(defaultStatus) {
	case StatusAffected:
		return StatusAffected, Evidence{MatchKind: "default", RangeString: "*"}
	case StatusUnaffected:
		return StatusUnaffected, Evidence{MatchKind: "default"}
	}
	return StatusUnknown, Evidence{MatchKind: "none"}
}

// effectiveStatus applies CVE 5.1 changes[]: the status of the latest change
// whose At is <= v wins; junk change versions fall back to the entry status.
func effectiveStatus(v Version, base Status, changes []VersionChange) Status {
	result := base
	var bestAt *Version
	for _, ch := range changes {
		at, err := Parse(ch.At)
		if err != nil || at.Wildcard {
			continue
		}
		if Compare(v, at) < 0 {
			continue
		}
		st := ch.Status
		if st != StatusAffected && st != StatusUnaffected {
			st = NormalizeStatus(string(ch.Status))
		}
		if st != StatusAffected && st != StatusUnaffected {
			continue
		}
		if bestAt == nil || Compare(at, *bestAt) > 0 {
			atCopy := at
			bestAt = &atCopy
			result = st
		}
	}
	return result
}

// BuildRangeStrings renders entries into canonical range expressions for the
// affected set and the unaffected set, each OR-joined with " || ". Range
// entries include their introduced lower bound: {version: "1.0.0",
// lessThan: "2.0.0"} renders ">= 1.0.0 < 2.0.0". Junk entries are skipped.
// When defaultStatus is affected and no affected entries rendered, the
// affected expression is "*".
func BuildRangeStrings(entries []VersionEntry, defaultStatus string) (versionRange, unaffectedVersions string) {
	affected, unaffected := buildRangeParts(entries)
	versionRange = strings.Join(affected, " || ")
	unaffectedVersions = strings.Join(unaffected, " || ")
	if versionRange == "" && NormalizeStatus(defaultStatus) == StatusAffected {
		versionRange = "*"
	}
	return versionRange, unaffectedVersions
}

// BuildRangeList renders entries into per-OR-group canonical strings (one
// element per affected range) for consumers that cannot split "||".
func BuildRangeList(entries []VersionEntry, defaultStatus string) []string {
	affected, _ := buildRangeParts(entries)
	if len(affected) == 0 && NormalizeStatus(defaultStatus) == StatusAffected {
		return []string{"*"}
	}
	return affected
}

func buildRangeParts(entries []VersionEntry) (affected, unaffected []string) {
	for _, e := range entries {
		rendered := renderEntry(e)
		if rendered == "" {
			continue
		}
		switch NormalizeStatus(string(e.Status)) {
		case StatusAffected:
			affected = append(affected, rendered)
		case StatusUnaffected:
			unaffected = append(unaffected, rendered)
		}
	}
	return affected, unaffected
}

// renderEntry renders one VersionEntry as a canonical constraint expression,
// or "" when the entry has no renderable content.
func renderEntry(e VersionEntry) string {
	lower, lowerOK := parseBound(e.Version)
	upperLt, upperLtOK := parseBoundPtr(e.LessThan)
	upperLte, upperLteOK := parseBoundPtr(e.LessThanOrEqual)
	isRange := upperLtOK || upperLteOK ||
		(e.LessThan != nil && isWildcardBound(*e.LessThan)) ||
		(e.LessThanOrEqual != nil && isWildcardBound(*e.LessThanOrEqual)) ||
		(lowerOK && lower.Wildcard)

	if !isRange {
		if !lowerOK {
			return ""
		}
		return "= " + renderVersion(lower)
	}

	var parts []string
	if lowerOK && !lower.Wildcard && !isZeroVersion(lower) {
		parts = append(parts, ">= "+renderVersion(lower))
	}
	if upperLtOK && !upperLt.Wildcard {
		parts = append(parts, "< "+renderVersion(upperLt))
	} else if upperLteOK && !upperLte.Wildcard {
		parts = append(parts, "<= "+renderVersion(upperLte))
	}
	if len(parts) == 0 {
		// Wildcard lower with no finite upper bound — all versions.
		return "*"
	}
	return strings.Join(parts, " ")
}

// DeriveFixedVersions extracts fix-version candidates from version entries,
// unifying the per-handler interpretations: an unaffected entry's version,
// or a range's lessThan / lessThanOrEqual boundary. Order-preserving,
// deduplicated. Values are passed through verbatim — git shas, letter
// versions ("1.0.2k"), and epoch versions ("1:2.4.5-1") are legitimate fix
// identifiers in some ecosystems, so no SemVer parse gate is applied.
func DeriveFixedVersions(entries []VersionEntry) []string {
	var out []string
	seen := make(map[string]bool)
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, e := range entries {
		switch {
		case e.LessThan != nil && *e.LessThan != "":
			add(*e.LessThan)
		case e.LessThanOrEqual != nil && *e.LessThanOrEqual != "":
			add(*e.LessThanOrEqual)
		case NormalizeStatus(string(e.Status)) == StatusUnaffected:
			add(e.Version)
		}
	}
	return out
}

func parseBound(s string) (Version, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Version{}, false
	}
	v, err := Parse(s)
	if err != nil {
		return Version{}, false
	}
	return v, true
}

func parseBoundPtr(s *string) (Version, bool) {
	if s == nil {
		return Version{}, false
	}
	return parseBound(*s)
}

func isWildcardBound(s string) bool {
	s = strings.TrimSpace(s)
	return s == "*" || s == "x" || s == "X"
}

func isZeroVersion(v Version) bool {
	if v.Major != 0 || v.Minor != 0 || v.Patch != 0 || v.Prerelease != "" {
		return false
	}
	for _, e := range v.Extra {
		if e != 0 {
			return false
		}
	}
	return true
}

// renderVersion renders a Version canonically (no v prefix, prerelease and
// build preserved).
func renderVersion(v Version) string {
	if v.Wildcard {
		return "*"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d.%d.%d", v.Major, v.Minor, v.Patch)
	for _, e := range v.Extra {
		fmt.Fprintf(&b, ".%d", e)
	}
	if v.Prerelease != "" {
		b.WriteByte('-')
		b.WriteString(v.Prerelease)
	}
	if v.Build != "" {
		b.WriteByte('+')
		b.WriteString(v.Build)
	}
	return b.String()
}
