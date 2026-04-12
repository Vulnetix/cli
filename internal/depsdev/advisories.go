package depsdev

import (
	"fmt"
	"strings"
)

// IsKnown returns true if the advisory ID or any of its aliases are already known.
func IsKnown(id string, aliases []string, known map[string]bool) bool {
	if known[id] {
		return true
	}
	for _, alias := range aliases {
		if known[alias] {
			return true
		}
	}
	return false
}

// NormalizeSeverity lowercases and validates a severity string.
func NormalizeSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "critical", "high", "medium", "low":
		return s
	default:
		return ""
	}
}

// AdvisoryCount returns the number of unique advisories across all enrichments
// that are NOT already known by the VDB.
func AdvisoryCount(enrichments []PackageEnrichment, existingIDs map[string]bool) int {
	seen := map[string]bool{}
	count := 0
	for _, e := range enrichments {
		for _, adv := range e.Advisories {
			id := adv.AdvisoryKey.ID
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			if !IsKnown(id, adv.Aliases, existingIDs) {
				count++
			}
		}
	}
	return count
}

// AdvisorySummary provides a brief summary string of advisory findings.
func AdvisorySummary(enrichments []PackageEnrichment, existingIDs map[string]bool) string {
	count := AdvisoryCount(enrichments, existingIDs)
	if count == 0 {
		return ""
	}
	if count == 1 {
		return "1 advisory from deps.dev (not in VDB)"
	}
	return fmt.Sprintf("%d advisories from deps.dev (not in VDB)", count)
}
