package scan

import "strings"

// ScoreToSeverity converts a numeric score of a given type to a severity label.
// Supported types: epss, coalition_ess (cess), cvss* variants.
// Returns "unscored" when the type is unrecognised or the score is zero.
func ScoreToSeverity(scoreType string, score float64) string {
	t := strings.ToLower(scoreType)
	switch {
	case t == "epss":
		// EPSS is a probability 0–1.
		switch {
		case score >= 0.9:
			return "critical"
		case score >= 0.5:
			return "high"
		case score >= 0.1:
			return "medium"
		case score > 0:
			return "low"
		default:
			return "unscored"
		}
	case t == "coalition_ess" || t == "cess":
		// Coalition ESS is 0–10, same bands as CVSS.
		switch {
		case score >= 9.0:
			return "critical"
		case score >= 7.0:
			return "high"
		case score >= 4.0:
			return "medium"
		case score > 0:
			return "low"
		default:
			return "unscored"
		}
	case strings.HasPrefix(t, "cvss"):
		// All CVSS variants use the NVD severity bands (0–10 scale).
		switch {
		case score >= 9.0:
			return "critical"
		case score >= 7.0:
			return "high"
		case score >= 4.0:
			return "medium"
		case score > 0:
			return "low"
		default:
			return "unscored"
		}
	default:
		return "unscored"
	}
}

// SSVCToSeverity maps an SSVC decision string to an approximate severity label.
// SSVC decisions are: Act, Attend, Track*, Track, Defer.
func SSVCToSeverity(decision string) string {
	switch strings.ToLower(decision) {
	case "act":
		return "critical"
	case "attend":
		return "high"
	case "track*":
		return "medium"
	case "track":
		return "low"
	case "defer":
		return "low"
	default:
		return "unscored"
	}
}

// SeverityLevel returns a numeric level for severity (higher = more severe).
// Used for threshold comparisons.
//
//	unscored → 0
//	low      → 1
//	medium   → 2
//	high     → 3
//	critical → 4
func SeverityLevel(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default: // unscored, info, unknown, ""
		return 0
	}
}

// SeverityMeetsThreshold reports whether the given severity meets or exceeds
// the threshold severity.  "unscored" never triggers the threshold.
// Examples:
//
//	SeverityMeetsThreshold("critical", "high")  → true
//	SeverityMeetsThreshold("medium",   "high")  → false
//	SeverityMeetsThreshold("high",     "high")  → true
//	SeverityMeetsThreshold("unscored", "low")   → false
func SeverityMeetsThreshold(severity, threshold string) bool {
	level := SeverityLevel(severity)
	if level == 0 {
		return false // unscored never matches
	}
	return level >= SeverityLevel(threshold)
}

// ValidSeverityThresholds lists the accepted --severity flag values in ascending order.
var ValidSeverityThresholds = []string{"low", "medium", "high", "critical"}
