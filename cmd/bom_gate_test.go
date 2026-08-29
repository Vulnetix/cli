package cmd

import (
	"testing"

	"github.com/vulnetix/cli/v3/internal/bom"
)

func TestParseBOMFailOn(t *testing.T) {
	tests := []struct {
		in      string
		wantErr bool
		check   func(bomFailOn) bool
	}{
		{"", false, func(f bomFailOn) bool { return f.empty() }},
		{"none", false, func(f bomFailOn) bool { return f.empty() }},
		{"any", false, func(f bomFailOn) bool { return f.any }},
		{"vuln-added", false, func(f bomFailOn) bool { return f.vulnAdded }},
		{"added,removed", false, func(f bomFailOn) bool { return f.added && f.removed }},
		{"downgraded, license-regression", false, func(f bomFailOn) bool {
			return f.downgraded && f.licenseRegression
		}},
		{"nonsense", true, nil},
	}
	for _, tt := range tests {
		got, err := parseBOMFailOn(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseBOMFailOn(%q) = nil error, want an error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseBOMFailOn(%q): %v", tt.in, err)
			continue
		}
		if !tt.check(got) {
			t.Errorf("parseBOMFailOn(%q) = %+v", tt.in, got)
		}
	}
}

// TestBOMDiffGateExitCode pins the CI contract: a breach is a policy breach,
// which exits 1 and suppresses the redundant error print because the command
// has already rendered the detail.
func TestBOMDiffGateExitCode(t *testing.T) {
	d := &bom.Diff{Summary: bom.DiffSummary{VulnsAdded: 2, Added: 1}}

	if err := evaluateBOMDiffGate(d, bomFailOn{}); err != nil {
		t.Errorf("empty gate returned %v, want nil", err)
	}
	if err := evaluateBOMDiffGate(d, bomFailOn{removed: true}); err != nil {
		t.Errorf("gate on an absent condition returned %v, want nil", err)
	}

	err := evaluateBOMDiffGate(d, bomFailOn{vulnAdded: true})
	if err == nil {
		t.Fatal("vuln-added gate did not breach on 2 introduced vulnerabilities")
	}
	if got := ExitCode(err); got != ExitFailure {
		t.Errorf("ExitCode = %d, want %d", got, ExitFailure)
	}
	if _, ok := err.(PolicyBreachError); !ok {
		t.Errorf("%T does not implement PolicyBreachError, so Execute will print it twice", err)
	}
}

// TestBOMQualityGateExitCode covers `bom validate --min-score`.
func TestBOMQualityGateExitCode(t *testing.T) {
	err := &bomGateError{gate: "sbom-quality", message: "score 40 is below the required 70"}
	if got := ExitCode(err); got != ExitFailure {
		t.Errorf("ExitCode = %d, want %d", got, ExitFailure)
	}
	if _, ok := error(err).(PolicyBreachError); !ok {
		t.Error("bomGateError must implement PolicyBreachError")
	}
}
