package depsdev

import (
	"testing"
)

func TestIsKnown(t *testing.T) {
	known := map[string]bool{
		"CVE-2021-1234": true,
		"GHSA-abcd-efgh": true,
	}

	tests := []struct {
		id      string
		aliases []string
		want    bool
	}{
		{"CVE-2021-1234", nil, true},
		{"GHSA-abcd-efgh", nil, true},
		{"GHSA-xxxx-yyyy", nil, false},
		{"GHSA-xxxx-yyyy", []string{"CVE-2021-1234"}, true},
		{"GHSA-xxxx-yyyy", []string{"CVE-2099-9999"}, false},
		{"", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got := IsKnown(tt.id, tt.aliases, known)
			if got != tt.want {
				t.Errorf("IsKnown(%q, %v) = %v, want %v", tt.id, tt.aliases, got, tt.want)
			}
		})
	}
}

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"CRITICAL", "critical"},
		{"High", "high"},
		{"medium", "medium"},
		{"LOW", "low"},
		{"  High  ", "high"},
		{"UNKNOWN", ""},
		{"", ""},
		{"moderate", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeSeverity(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeSeverity(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestAdvisoryCount(t *testing.T) {
	enrichments := []PackageEnrichment{
		{
			PackageRef: PackageRef{Name: "foo", Version: "1.0.0", Ecosystem: "npm"},
			Advisories: []AdvisoryResponse{
				{AdvisoryKey: AdvisoryKey{ID: "GHSA-1111"}, Aliases: []string{"CVE-2021-1111"}},
				{AdvisoryKey: AdvisoryKey{ID: "GHSA-2222"}},
			},
		},
		{
			PackageRef: PackageRef{Name: "bar", Version: "2.0.0", Ecosystem: "npm"},
			Advisories: []AdvisoryResponse{
				{AdvisoryKey: AdvisoryKey{ID: "GHSA-3333"}},
				{AdvisoryKey: AdvisoryKey{ID: "GHSA-1111"}}, // duplicate
			},
		},
	}

	// No existing IDs — all 3 unique advisories should count.
	count := AdvisoryCount(enrichments, nil)
	if count != 3 {
		t.Errorf("AdvisoryCount with no existing = %d, want 3", count)
	}

	// CVE-2021-1111 already known — GHSA-1111 should be excluded.
	existing := map[string]bool{"CVE-2021-1111": true}
	count = AdvisoryCount(enrichments, existing)
	if count != 2 {
		t.Errorf("AdvisoryCount with CVE known = %d, want 2", count)
	}

	// GHSA-2222 and GHSA-3333 known — only GHSA-1111 remains (but its alias is not known).
	existing2 := map[string]bool{"GHSA-2222": true, "GHSA-3333": true}
	count = AdvisoryCount(enrichments, existing2)
	if count != 1 {
		t.Errorf("AdvisoryCount with GHSAs known = %d, want 1", count)
	}
}

func TestAdvisorySummary(t *testing.T) {
	tests := []struct {
		name     string
		enrichments []PackageEnrichment
		existing map[string]bool
		want     string
	}{
		{
			name:        "no advisories",
			enrichments: nil,
			want:        "",
		},
		{
			name: "one advisory",
			enrichments: []PackageEnrichment{
				{Advisories: []AdvisoryResponse{{AdvisoryKey: AdvisoryKey{ID: "GHSA-1"}}}},
			},
			want: "1 advisory from deps.dev (not in VDB)",
		},
		{
			name: "multiple advisories",
			enrichments: []PackageEnrichment{
				{Advisories: []AdvisoryResponse{
					{AdvisoryKey: AdvisoryKey{ID: "GHSA-1"}},
					{AdvisoryKey: AdvisoryKey{ID: "GHSA-2"}},
				}},
			},
			want: "2 advisories from deps.dev (not in VDB)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AdvisorySummary(tt.enrichments, tt.existing)
			if got != tt.want {
				t.Errorf("AdvisorySummary() = %q, want %q", got, tt.want)
			}
		})
	}
}
