package fix

import (
	"fmt"

	"github.com/vulnetix/cli/v3/pkg/vdb"
)

type TargetDecision struct {
	Skipped bool
	Reason  string
	// Note is set when the target was chosen by a different route than the
	// strategy asked for, so the caller can print one line saying so.
	Note string
}

// noRollingSetNote is what a rolling run says when the server gave it no set to
// pick from and the stable logic stood in.
const noRollingSetNote = "server did not return a rolling set; using stable"

func ResolveTarget(current string, strategy Strategy, latest []vdb.CliVersionStamp, safe []vdb.CliSafeHarbourVersion, summary *vdb.CliSafeHarbourSummary, maxMajorBump int) (string, TargetDecision) {
	current = normalizeVersion(current)
	target := serverPick(strategy, summary)
	var note string
	if target == "" {
		if strategy == StrategyRolling {
			note = noRollingSetNote
			if summary != nil && summary.Picks != nil {
				note = "no rolling target"
				if why := summary.Picks.Reasons[string(StrategyRolling)]; why != "" {
					note += " (" + why + ")"
				}
				note += "; using stable"
			}
		}
		target = localPick(current, strategy, latest, safe)
	}
	if target == "" && summary != nil {
		if summary.Recommendation != nil {
			target = normalizeVersion(summary.Recommendation.Version)
		}
		if target == "" && len(summary.RecommendedVersions) > 0 {
			target = normalizeVersion(summary.RecommendedVersions[0])
		}
	}
	skip := func(reason string) (string, TargetDecision) {
		return "", TargetDecision{Skipped: true, Reason: reason, Note: note}
	}
	if target == "" {
		return skip("no Safe-Harbour fix version available")
	}
	if current != "" && normalizeVersion(target) == current {
		return skip(fmt.Sprintf("target %s is already installed", target))
	}
	if current != "" && lessThan(target, current) {
		return skip(fmt.Sprintf("target %s would downgrade from %s", target, current))
	}
	if maxMajorBump >= 0 && current != "" {
		curMajor, okCur := majorOf(current)
		tgtMajor, okTarget := majorOf(target)
		if okCur && okTarget && int(tgtMajor-curMajor) > maxMajorBump {
			return skip(fmt.Sprintf("target %s crosses more than %d major version(s)", target, maxMajorBump))
		}
	}
	return target, TargetDecision{Note: note}
}

// serverPick reads the version the server chose for the strategy, or "" when
// the server sent no picks (an older server) or could not make this one.
func serverPick(strategy Strategy, summary *vdb.CliSafeHarbourSummary) string {
	if summary == nil || summary.Picks == nil {
		return ""
	}
	p := summary.Picks
	switch strategy {
	case StrategyLatest:
		return normalizeVersion(p.Latest)
	case StrategySafest:
		return normalizeVersion(p.Safest)
	case StrategyRolling:
		return normalizeVersion(p.RollingTarget)
	default:
		return normalizeVersion(p.Stable)
	}
}

// localPick derives the target from the ranked safe versions, for a server that
// sent no picks or left this one empty. Rolling has no local equivalent and
// uses the stable logic.
func localPick(current string, strategy Strategy, latest []vdb.CliVersionStamp, safe []vdb.CliSafeHarbourVersion) string {
	switch strategy {
	case StrategyLatest:
		if len(latest) > 0 {
			if v := normalizeVersion(latest[0].Version); v != "" {
				return v
			}
		}
		return newestSafeVersion(safe)
	case StrategySafest:
		return safestVersion(safe)
	default:
		return stableVersion(current, safe)
	}
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
