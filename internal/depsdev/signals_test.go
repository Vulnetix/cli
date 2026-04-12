package depsdev

import (
	"testing"
)

func TestScorecardSeverity(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{0, "critical"},
		{1.5, "critical"},
		{2.0, "high"},
		{3.9, "high"},
		{4.0, "medium"},
		{5.5, "medium"},
		{6.0, "low"},
		{8.0, "low"},
		{10.0, "low"},
	}

	for _, tt := range tests {
		got := ScorecardSeverity(tt.score)
		if got != tt.want {
			t.Errorf("ScorecardSeverity(%.1f) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestSummarizeSignals(t *testing.T) {
	t.Run("all signals present", func(t *testing.T) {
		enrichments := []PackageEnrichment{
			{
				PackageRef: PackageRef{Name: "pkg-a", Version: "1.0.0", Ecosystem: "npm"},
				Project: &ProjectResponse{
					ProjectKey: ProjectKey{ID: "github.com/a/a"},
					Scorecard:  &Scorecard{OverallScore: 2.5},
				},
				VersionData: &VersionResponse{
					SLSAProvenances: []SLSAProvenance{{Verified: true}},
				},
				IsOutdated:     true,
				VersionsBehind: 5,
			},
			{
				PackageRef: PackageRef{Name: "pkg-b", Version: "2.0.0", Ecosystem: "npm"},
				VersionData: &VersionResponse{}, // no provenance
				IsOutdated:     true,
				VersionsBehind: 10,
			},
		}

		s := SummarizeSignals(enrichments)
		if s.LowScorecardCount != 1 {
			t.Errorf("LowScorecardCount = %d, want 1", s.LowScorecardCount)
		}
		if s.MissingProvenanceCount != 1 {
			t.Errorf("MissingProvenanceCount = %d, want 1", s.MissingProvenanceCount)
		}
		if s.OutdatedCount != 2 {
			t.Errorf("OutdatedCount = %d, want 2", s.OutdatedCount)
		}
	})

	t.Run("no provenance flagged when none have it", func(t *testing.T) {
		enrichments := []PackageEnrichment{
			{
				PackageRef:  PackageRef{Name: "pkg-a", Version: "1.0.0", Ecosystem: "npm"},
				VersionData: &VersionResponse{}, // no provenance
			},
			{
				PackageRef:  PackageRef{Name: "pkg-b", Version: "2.0.0", Ecosystem: "npm"},
				VersionData: &VersionResponse{}, // no provenance
			},
		}

		s := SummarizeSignals(enrichments)
		if s.MissingProvenanceCount != 0 {
			t.Errorf("MissingProvenanceCount = %d, want 0 (no packages have provenance)", s.MissingProvenanceCount)
		}
	})

	t.Run("outdated only counted at threshold", func(t *testing.T) {
		enrichments := []PackageEnrichment{
			{
				PackageRef:     PackageRef{Name: "pkg-a", Version: "1.0.0", Ecosystem: "npm"},
				IsOutdated:     true,
				VersionsBehind: 1, // below threshold
			},
			{
				PackageRef:     PackageRef{Name: "pkg-b", Version: "1.0.0", Ecosystem: "npm"},
				IsOutdated:     true,
				VersionsBehind: 2, // at threshold
			},
		}

		s := SummarizeSignals(enrichments)
		if s.OutdatedCount != 1 {
			t.Errorf("OutdatedCount = %d, want 1", s.OutdatedCount)
		}
	})

	t.Run("high scorecard not counted", func(t *testing.T) {
		enrichments := []PackageEnrichment{
			{
				PackageRef: PackageRef{Name: "pkg-a", Version: "1.0.0", Ecosystem: "npm"},
				Project: &ProjectResponse{
					ProjectKey: ProjectKey{ID: "github.com/a/a"},
					Scorecard:  &Scorecard{OverallScore: 7.5},
				},
			},
		}

		s := SummarizeSignals(enrichments)
		if s.LowScorecardCount != 0 {
			t.Errorf("LowScorecardCount = %d, want 0", s.LowScorecardCount)
		}
	})

	t.Run("empty enrichments", func(t *testing.T) {
		s := SummarizeSignals(nil)
		if s.LowScorecardCount != 0 || s.MissingProvenanceCount != 0 || s.OutdatedCount != 0 {
			t.Error("expected all zeros for empty enrichments")
		}
	})
}
