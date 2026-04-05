package scan

import (
	"testing"
)

// ── ScoreToSeverity ──────────────────────────────────────────────────────────

func TestScoreToSeverity_EPSS(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{0.95, "critical"},
		{0.90, "critical"},
		{0.89, "high"},
		{0.50, "high"},
		{0.49, "medium"},
		{0.10, "medium"},
		{0.09, "low"},
		{0.001, "low"},
		{0.0, "unscored"},
	}
	for _, tt := range tests {
		got := ScoreToSeverity("epss", tt.score)
		if got != tt.want {
			t.Errorf("ScoreToSeverity(epss, %.3f) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestScoreToSeverity_CoalitionESS(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{9.0, "critical"},
		{10.0, "critical"},
		{8.9, "high"},
		{7.0, "high"},
		{6.9, "medium"},
		{4.0, "medium"},
		{3.9, "low"},
		{0.1, "low"},
		{0.0, "unscored"},
	}
	for _, tt := range tests {
		for _, t2 := range []string{"coalition_ess", "cess"} {
			got := ScoreToSeverity(t2, tt.score)
			if got != tt.want {
				t.Errorf("ScoreToSeverity(%s, %.1f) = %q, want %q", t2, tt.score, got, tt.want)
			}
		}
	}
}

func TestScoreToSeverity_CVSS(t *testing.T) {
	tests := []struct {
		scoreType string
		score     float64
		want      string
	}{
		{"cvssv3.1", 9.0, "critical"},
		{"cvssv3.1", 10.0, "critical"},
		{"cvssv3.1", 8.9, "high"},
		{"cvssv3.1", 7.0, "high"},
		{"cvssv3.1", 6.9, "medium"},
		{"cvssv3.1", 4.0, "medium"},
		{"cvssv3.1", 3.9, "low"},
		{"cvssv3.1", 0.1, "low"},
		{"cvssv3.1", 0.0, "unscored"},
		{"cvssv2", 9.0, "critical"},
		{"cvss4", 9.0, "critical"},
		{"CVSSV3.1", 7.5, "high"}, // case-insensitive
	}
	for _, tt := range tests {
		got := ScoreToSeverity(tt.scoreType, tt.score)
		if got != tt.want {
			t.Errorf("ScoreToSeverity(%s, %.1f) = %q, want %q", tt.scoreType, tt.score, got, tt.want)
		}
	}
}

func TestScoreToSeverity_Unknown(t *testing.T) {
	got := ScoreToSeverity("unknowntype", 9.9)
	if got != "unscored" {
		t.Errorf("expected unscored for unknown score type, got %q", got)
	}
}

// ── SSVCToSeverity ───────────────────────────────────────────────────────────

func TestSSVCToSeverity(t *testing.T) {
	tests := []struct {
		decision string
		want     string
	}{
		{"Act", "critical"},
		{"act", "critical"},
		{"ACT", "critical"},
		{"Attend", "high"},
		{"Track*", "medium"},
		{"track*", "medium"},
		{"Track", "low"},
		{"Defer", "low"},
		{"defer", "low"},
		{"", "unscored"},
		{"unknown", "unscored"},
	}
	for _, tt := range tests {
		got := SSVCToSeverity(tt.decision)
		if got != tt.want {
			t.Errorf("SSVCToSeverity(%q) = %q, want %q", tt.decision, got, tt.want)
		}
	}
}

// ── SeverityLevel ────────────────────────────────────────────────────────────

func TestSeverityLevel(t *testing.T) {
	tests := []struct {
		sev  string
		want int
	}{
		{"critical", 4},
		{"CRITICAL", 4},
		{"high", 3},
		{"HIGH", 3},
		{"medium", 2},
		{"low", 1},
		{"unscored", 0},
		{"", 0},
		{"info", 0},
		{"unknown", 0},
	}
	for _, tt := range tests {
		got := SeverityLevel(tt.sev)
		if got != tt.want {
			t.Errorf("SeverityLevel(%q) = %d, want %d", tt.sev, got, tt.want)
		}
	}
}

// ── SeverityMeetsThreshold ───────────────────────────────────────────────────

func TestSeverityMeetsThreshold(t *testing.T) {
	tests := []struct {
		sev       string
		threshold string
		want      bool
	}{
		// critical meets all
		{"critical", "low", true},
		{"critical", "medium", true},
		{"critical", "high", true},
		{"critical", "critical", true},

		// high meets medium and above
		{"high", "low", true},
		{"high", "medium", true},
		{"high", "high", true},
		{"high", "critical", false},

		// medium meets low and medium
		{"medium", "low", true},
		{"medium", "medium", true},
		{"medium", "high", false},
		{"medium", "critical", false},

		// low meets only low
		{"low", "low", true},
		{"low", "medium", false},
		{"low", "high", false},
		{"low", "critical", false},

		// unscored never meets any threshold
		{"unscored", "low", false},
		{"unscored", "medium", false},
		{"unscored", "high", false},
		{"unscored", "critical", false},

		// empty string is treated as unscored
		{"", "low", false},
	}
	for _, tt := range tests {
		got := SeverityMeetsThreshold(tt.sev, tt.threshold)
		if got != tt.want {
			t.Errorf("SeverityMeetsThreshold(%q, %q) = %v, want %v", tt.sev, tt.threshold, got, tt.want)
		}
	}
}

// ── computeEnrichedSeverities ────────────────────────────────────────────────

func TestComputeEnrichedSeverities_MaxSeverity(t *testing.T) {
	tests := []struct {
		name        string
		ev          EnrichedVuln
		wantMax     string
		wantCVSS    string
		wantEPSS    string
		wantCESS    string
		wantSSVC    string
	}{
		{
			name: "CVSS drives max",
			ev: EnrichedVuln{
				VulnFinding: VulnFinding{Score: 9.5, MetricType: "cvssv3.1"},
			},
			wantMax:  "critical",
			wantCVSS: "critical",
			wantEPSS: "",
			wantCESS: "",
			wantSSVC: "",
		},
		{
			name: "EPSS drives max over low CVSS",
			ev: EnrichedVuln{
				VulnFinding: VulnFinding{Score: 3.5, MetricType: "cvssv3.1"},
				EPSSScore:   0.95,
			},
			wantMax:  "critical",
			wantCVSS: "low",
			wantEPSS: "critical",
		},
		{
			name: "SSVC Act drives max",
			ev: EnrichedVuln{
				SSVCDecision: "Act",
			},
			wantMax:  "critical",
			wantSSVC: "critical",
		},
		{
			name: "Coalition ESS drives max",
			ev: EnrichedVuln{
				CoalitionESS: 7.5,
			},
			wantMax:  "high",
			wantCESS: "high",
		},
		{
			name: "No scores → unscored",
			ev:   EnrichedVuln{},
			wantMax: "unscored",
		},
		{
			name: "Base Severity string contributes",
			ev: EnrichedVuln{
				VulnFinding: VulnFinding{Severity: "critical"},
			},
			wantMax: "critical",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := tt.ev
			computeEnrichedSeverities(&ev)
			if ev.MaxSeverity != tt.wantMax {
				t.Errorf("MaxSeverity = %q, want %q", ev.MaxSeverity, tt.wantMax)
			}
			if tt.wantCVSS != "" && ev.CVSSSeverity != tt.wantCVSS {
				t.Errorf("CVSSSeverity = %q, want %q", ev.CVSSSeverity, tt.wantCVSS)
			}
			if tt.wantEPSS != "" && ev.EPSSSeverity != tt.wantEPSS {
				t.Errorf("EPSSSeverity = %q, want %q", ev.EPSSSeverity, tt.wantEPSS)
			}
			if tt.wantCESS != "" && ev.CESSeverity != tt.wantCESS {
				t.Errorf("CESSeverity = %q, want %q", ev.CESSeverity, tt.wantCESS)
			}
			if tt.wantSSVC != "" && ev.SSVCSeverity != tt.wantSSVC {
				t.Errorf("SSVCSeverity = %q, want %q", ev.SSVCSeverity, tt.wantSSVC)
			}
		})
	}
}
