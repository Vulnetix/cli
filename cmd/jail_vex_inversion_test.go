package cmd

import (
	"encoding/json"
	"testing"

	"github.com/vulnetix/cli/v3/internal/triage"
)

// TestOpenVEXInversionIsReal proves the justification fallback in writeJailVEX
// is load-bearing rather than defensive decoration.
//
// It feeds triage.GenerateOpenVEX the exact shape writeJailVEX protects against
// — affected, carrying a fix version, with no justification — and asserts the
// writer really does rewrite it to not_affected (internal/triage/vex.go). That
// rewrite is correct for the interactive triage path it was written for, and
// catastrophic for a jail: a jail statement means "affected, past policy, AND a
// fix exists", so an unjustified one would publish a document telling every
// downstream consumer the repository is NOT affected by the very
// vulnerabilities that failed its build.
//
// If this test ever starts skipping because GenerateOpenVEX changed, the
// fallback in writeJailVEX can be revisited. Until then it is the only thing
// standing between a jail verdict and a document asserting its opposite.
func TestOpenVEXInversionIsReal(t *testing.T) {
	body, err := triage.GenerateOpenVEX([]*triage.TriageFinding{{
		CVEID:        "CVE-2024-0001",
		Package:      "left-pad",
		Ecosystem:    "npm",
		InstalledVer: "1.0.0",
		FixedVer:     "1.3.0",
		Status:       "affected",
		// Justification deliberately empty — this is the shape under test.
	}}, triage.OpenVEXOptions{ID: "urn:test:inversion"})
	if err != nil {
		t.Fatalf("GenerateOpenVEX: %v", err)
	}

	var doc struct {
		Statements []struct {
			Status        string `json:"status"`
			Justification string `json:"justification"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("statements = %d, want 1", len(doc.Statements))
	}

	if doc.Statements[0].Status != "not_affected" {
		t.Skipf("GenerateOpenVEX no longer inverts an unjustified statement (status %q); "+
			"the justification fallback in writeJailVEX may now be unnecessary",
			doc.Statements[0].Status)
	}
	if doc.Statements[0].Justification != "vulnerable_code_not_present" {
		t.Fatalf("justification = %q, want vulnerable_code_not_present",
			doc.Statements[0].Justification)
	}
}
