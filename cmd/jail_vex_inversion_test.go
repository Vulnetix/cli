package cmd

import (
	"encoding/json"
	"testing"

	"github.com/vulnetix/cli/v3/internal/triage"
)

// TestOpenVEXDoesNotInvertAffected feeds triage.GenerateOpenVEX the shape a
// jail statement has (affected, carrying a fix version, no justification) and
// asserts it stays affected.
//
// The writer used to rewrite exactly this to not_affected with
// vulnerable_code_not_present, and writeJailVEX forced a justification onto
// every statement to dodge it. A jail document asserting that the repository
// is not affected by the vulnerabilities that failed its build would be worse
// than no document, so the non-inversion is pinned here rather than left to
// the fallback.
func TestOpenVEXDoesNotInvertAffected(t *testing.T) {
	body, err := triage.GenerateOpenVEX([]*triage.TriageFinding{{
		CVEID:        "CVE-2024-0001",
		Package:      "left-pad",
		Ecosystem:    "npm",
		InstalledVer: "1.0.0",
		FixedVer:     "1.3.0",
		Status:       "affected",
	}}, triage.OpenVEXOptions{ID: "urn:test:inversion"})
	if err != nil {
		t.Fatalf("GenerateOpenVEX: %v", err)
	}

	var doc struct {
		Statements []struct {
			Status          string `json:"status"`
			Justification   string `json:"justification"`
			ActionStatement string `json:"action_statement"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("statements = %d, want 1", len(doc.Statements))
	}
	s := doc.Statements[0]
	if s.Status != "affected" {
		t.Fatalf("status = %q, want affected", s.Status)
	}
	if s.Justification != "" {
		t.Fatalf("justification = %q on an affected statement", s.Justification)
	}
	if s.ActionStatement == "" {
		t.Fatal("affected statement has no action_statement")
	}
}
