package depsdev

// ScorecardSeverity maps an OpenSSF Scorecard overall score to a severity string.
// Lower scores indicate higher risk.
func ScorecardSeverity(score float64) string {
	switch {
	case score < 2:
		return "critical"
	case score < 4:
		return "high"
	case score < 6:
		return "medium"
	default:
		return "low"
	}
}

// SignalSummary provides counts of supply-chain signals found.
type SignalSummary struct {
	LowScorecardCount     int
	MissingProvenanceCount int
	OutdatedCount          int
}

// SummarizeSignals counts supply-chain signals across all enrichments.
func SummarizeSignals(enrichments []PackageEnrichment) SignalSummary {
	var s SignalSummary
	seenProjects := map[string]bool{}
	hasAnyProvenance := false

	for _, e := range enrichments {
		// Scorecard
		if e.Project != nil && e.Project.Scorecard != nil && e.Project.Scorecard.OverallScore < 4.0 {
			pid := e.Project.ProjectKey.ID
			if pid == "" {
				pid = e.Ecosystem + "/" + e.Name
			}
			if !seenProjects[pid] {
				seenProjects[pid] = true
				s.LowScorecardCount++
			}
		}

		// Provenance
		if e.VersionData != nil && len(e.VersionData.SLSAProvenances) > 0 {
			hasAnyProvenance = true
		}

		// Outdated
		if e.IsOutdated && e.VersionsBehind >= 2 {
			s.OutdatedCount++
		}
	}

	// Only count missing provenance if at least one package has it.
	if hasAnyProvenance {
		for _, e := range enrichments {
			if e.VersionData != nil && len(e.VersionData.SLSAProvenances) == 0 {
				s.MissingProvenanceCount++
			}
		}
	}

	return s
}
