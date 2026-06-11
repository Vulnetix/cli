package fix

import (
	"sort"
	"strings"

	semver "github.com/Masterminds/semver/v3"

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
func Satisfies(version, constraint string) bool {
	version = normalizeVersion(version)
	constraint = strings.TrimSpace(constraint)
	if version == "" || constraint == "" || constraint == "*" {
		return constraint == "" || constraint == "*"
	}
	c, err := semver.NewConstraint(constraint)
	if err != nil {
		return strings.TrimPrefix(version, "v") == strings.TrimPrefix(constraint, "v")
	}
	v, err := semver.NewVersion(version)
	if err != nil {
		return false
	}
	return c.Check(v)
}

func BestInRange(candidates []string, constraint string) string {
	versions := sortableVersions(candidates, false)
	for _, v := range versions {
		if Satisfies(v, constraint) {
			return v
		}
	}
	return ""
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
