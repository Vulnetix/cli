package fix

import (
	"sort"

	semver "github.com/Masterminds/semver/v3"

	manifest "github.com/Vulnetix/vdb-manifest"

	vers "github.com/vulnetix/cli/v3/internal/versions"
)

// Satisfies reports whether version satisfies an npm-style constraint
// (^, ~, ranges) via Masterminds/semver.
//
// NOTE: Masterminds constraints EXCLUDE prerelease versions unless the
// constraint itself contains one (">= 1.0.0" does not match "1.2.0-beta").
// That posture is acceptable here because Satisfies is only used for
// fix-version SELECTION (picking an upgrade target); it must never be used
// for affected-status determination — that lives in internal/versions,
// where prereleases are included in vulnerability ranges.
//
// The implementation is shared with the server through
// github.com/Vulnetix/vdb-manifest.
func Satisfies(version, constraint string) bool {
	return manifest.Satisfies(version, constraint)
}

// BestInRange returns the highest candidate that satisfies constraint, or "".
func BestInRange(candidates []string, constraint string) string {
	return manifest.BestInRange(candidates, constraint)
}

func normalizeVersion(v string) string {
	return vers.Normalize(v)
}

func sortableVersions(input []string, asc bool) []string {
	out := make([]string, 0, len(input))
	for _, raw := range input {
		v := normalizeVersion(raw)
		if _, err := semver.NewVersion(v); err == nil {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		vi, _ := semver.NewVersion(out[i])
		vj, _ := semver.NewVersion(out[j])
		if asc {
			return vi.LessThan(vj)
		}
		return vj.LessThan(vi)
	})
	return out
}

func majorOf(v string) (int64, bool) {
	parsed, err := semver.NewVersion(normalizeVersion(v))
	if err != nil {
		return 0, false
	}
	return int64(parsed.Major()), true
}

func lessThan(a, b string) bool {
	va, errA := semver.NewVersion(normalizeVersion(a))
	vb, errB := semver.NewVersion(normalizeVersion(b))
	return errA == nil && errB == nil && va.LessThan(vb)
}

func greaterOrEqual(a, b string) bool {
	va, errA := semver.NewVersion(normalizeVersion(a))
	vb, errB := semver.NewVersion(normalizeVersion(b))
	return errA == nil && errB == nil && !va.LessThan(vb)
}
