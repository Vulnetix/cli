package fix

import (
	"fmt"

	"github.com/vulnetix/cli/v3/pkg/vdb"
)

type TargetDecision struct {
	Skipped bool
	Reason  string
}

func ResolveTarget(current string, strategy Strategy, latest []vdb.CliVersionStamp, safe []vdb.CliSafeHarbourVersion, summary *vdb.CliSafeHarbourSummary, maxMajorBump int) (string, TargetDecision) {
	current = normalizeVersion(current)
	var target string
	switch strategy {
	case StrategyLatest:
		if len(latest) > 0 {
			target = normalizeVersion(latest[0].Version)
		}
		if target == "" {
			target = newestSafeVersion(safe)
		}
	case StrategySafest:
		target = safestVersion(safe)
	case StrategyStable:
		target = stableVersion(current, safe)
	default:
		target = stableVersion(current, safe)
	}
	if target == "" && summary != nil {
		if summary.Recommendation != nil {
			target = normalizeVersion(summary.Recommendation.Version)
		}
		if target == "" && len(summary.RecommendedVersions) > 0 {
			target = normalizeVersion(summary.RecommendedVersions[0])
		}
	}
	if target == "" {
		return "", TargetDecision{Skipped: true, Reason: "no Safe-Harbour fix version available"}
	}
	if current != "" && lessThan(target, current) {
		return "", TargetDecision{Skipped: true, Reason: fmt.Sprintf("target %s would downgrade from %s", target, current)}
	}
	if maxMajorBump >= 0 && current != "" {
		curMajor, okCur := majorOf(current)
		tgtMajor, okTarget := majorOf(target)
		if okCur && okTarget && int(tgtMajor-curMajor) > maxMajorBump {
			return "", TargetDecision{Skipped: true, Reason: fmt.Sprintf("target %s crosses more than %d major version(s)", target, maxMajorBump)}
		}
	}
	return target, TargetDecision{}
}

func stableVersion(current string, safe []vdb.CliSafeHarbourVersion) string {
	candidates := safeVersionStrings(safe, true)
	for _, v := range sortableVersions(candidates, true) {
		if current == "" || greaterOrEqual(v, current) {
			return v
		}
	}
	return newestSafeVersion(safe)
}

func newestSafeVersion(safe []vdb.CliSafeHarbourVersion) string {
	candidates := safeVersionStrings(safe, true)
	sorted := sortableVersions(candidates, false)
	if len(sorted) == 0 {
		return ""
	}
	return sorted[0]
}

func safestVersion(safe []vdb.CliSafeHarbourVersion) string {
	var best vdb.CliSafeHarbourVersion
	found := false
	for _, s := range safe {
		if !isUsableSafeVersion(s) {
			continue
		}
		if !found || s.SafeHarbourScore > best.SafeHarbourScore || (s.SafeHarbourScore == best.SafeHarbourScore && lessThan(best.Version, s.Version)) {
			best = s
			found = true
		}
	}
	if !found {
		return ""
	}
	return normalizeVersion(best.Version)
}

func safeVersionStrings(safe []vdb.CliSafeHarbourVersion, usableOnly bool) []string {
	out := make([]string, 0, len(safe))
	for _, s := range safe {
		if usableOnly && !isUsableSafeVersion(s) {
			continue
		}
		if s.Version != "" {
			out = append(out, s.Version)
		}
	}
	return out
}

func isUsableSafeVersion(s vdb.CliSafeHarbourVersion) bool {
	return s.Version != "" && !s.IsMalware && s.VulnerabilityCount == 0 && s.ExploitCount == 0
}
