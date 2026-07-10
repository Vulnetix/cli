package memory

import "testing"

// alwaysGone is a Verifier that reports the evidence has left disk.
func alwaysGone(Location) (bool, string) { return true, "file deleted" }

// neverGone is a Verifier that reports the evidence is still on disk.
func neverGone(Location) (bool, string) { return false, "snippet still present" }

func TestDefaultResolutionMode(t *testing.T) {
	verify := []string{ToolSAST, ToolSecrets, ToolIaC, ToolContainer}
	for _, tool := range verify {
		if got := DefaultResolutionMode(tool); got != ResolveOnVerify {
			t.Errorf("%s: got mode %q, want %q", tool, got, ResolveOnVerify)
		}
	}
	absence := []string{ToolSCA, ToolLicense, ToolCBOM, ToolAIBOM, ToolMalscan, ToolQuality}
	for _, tool := range absence {
		if got := DefaultResolutionMode(tool); got != ResolveOnAbsence {
			t.Errorf("%s: got mode %q, want %q", tool, got, ResolveOnAbsence)
		}
	}
}

// A container finding must never be auto-resolved on absence alone. Before the
// resolution-mode split, ReconcileTool routed ToolContainer through the SCA arm,
// which ignored the Verifier entirely: a `vulnetix secrets` run (which evaluates
// no Dockerfile rules) silently marked every prior container finding as fixed.
func TestReconcileTool_ContainerRequiresVerifiedRemoval(t *testing.T) {
	newMem := func() *Memory {
		return &Memory{
			Version: "1",
			Findings: map[string]FindingRecord{
				"fp-container": {
					Tool:      ToolContainer,
					Status:    "affected",
					Locations: []Location{{File: "Dockerfile", StartLine: 3, Snippet: "USER root"}},
				},
			},
		}
	}

	t.Run("evidence still on disk leaves the record untouched", func(t *testing.T) {
		m := newMem()
		changes := m.ReconcileTool(ReconcileContext{
			Tool:       ToolContainer,
			CurrentIDs: map[string]bool{},
			Verifier:   neverGone,
		})
		if len(changes) != 0 {
			t.Fatalf("expected no state changes, got %d: %+v", len(changes), changes)
		}
		if got := m.Findings["fp-container"].Status; got != "affected" {
			t.Errorf("status = %q, want affected", got)
		}
	})

	t.Run("no verifier resolves nothing", func(t *testing.T) {
		m := newMem()
		changes := m.ReconcileTool(ReconcileContext{
			Tool:       ToolContainer,
			CurrentIDs: map[string]bool{},
		})
		if len(changes) != 0 {
			t.Fatalf("expected no state changes without a verifier, got %+v", changes)
		}
		if got := m.Findings["fp-container"].Status; got != "affected" {
			t.Errorf("status = %q, want affected", got)
		}
	})

	t.Run("verified removal resolves and reports the change", func(t *testing.T) {
		m := newMem()
		changes := m.ReconcileTool(ReconcileContext{
			Tool:       ToolContainer,
			CurrentIDs: map[string]bool{},
			Verifier:   alwaysGone,
		})
		if len(changes) != 1 {
			t.Fatalf("expected 1 state change, got %d", len(changes))
		}
		if changes[0].NewStatus != "fixed" || changes[0].Tool != ToolContainer {
			t.Errorf("got %+v", changes[0])
		}
		if got := m.Findings["fp-container"].Status; got != "fixed" {
			t.Errorf("status = %q, want fixed", got)
		}
	})
}

func TestReconcileTool_AbsenceResolvesInventoryTools(t *testing.T) {
	for _, tool := range []string{ToolLicense, ToolCBOM, ToolAIBOM, ToolMalscan} {
		t.Run(tool, func(t *testing.T) {
			m := &Memory{
				Version:  "1",
				Findings: map[string]FindingRecord{"id-1": {Tool: tool, Status: "affected"}},
			}
			changes := m.ReconcileTool(ReconcileContext{
				Tool:       tool,
				CurrentIDs: map[string]bool{},
			})
			if len(changes) != 1 {
				t.Fatalf("expected 1 state change, got %d", len(changes))
			}
			if changes[0].NewStatus != "fixed" {
				t.Errorf("NewStatus = %q, want fixed", changes[0].NewStatus)
			}
			if changes[0].Comment == "" {
				t.Error("expected a non-empty resolution comment")
			}
		})
	}
}

func TestReconcileTool_BranchGating(t *testing.T) {
	m := &Memory{
		Version: "1",
		Findings: map[string]FindingRecord{
			"CVE-1": {Tool: ToolSCA, Status: "affected", LastSeenBranch: "main"},
			"CVE-2": {Tool: ToolSCA, Status: "affected", LastSeenBranch: "feature/x"},
			"CVE-3": {Tool: ToolSCA, Status: "affected"}, // no branch recorded
		},
	}
	changes := m.ReconcileTool(ReconcileContext{
		Tool:       ToolSCA,
		CurrentIDs: map[string]bool{},
		Branch:     "feature/x",
	})
	if len(changes) != 2 {
		t.Fatalf("expected 2 state changes (feature/x + unbranched), got %d", len(changes))
	}
	if m.Findings["CVE-1"].Status != "affected" {
		t.Error("a finding recorded on main must not be resolved while scanning feature/x")
	}
	if m.Findings["CVE-2"].Status != "fixed" {
		t.Error("same-branch finding should have been resolved")
	}
	if m.Findings["CVE-3"].Status != "fixed" {
		t.Error("finding with no recorded branch should have been resolved")
	}
}

func TestReconcileTool_RegressionStatus(t *testing.T) {
	t.Run("default returns to under_investigation", func(t *testing.T) {
		m := &Memory{
			Version:  "1",
			Findings: map[string]FindingRecord{"CVE-1": {Tool: ToolSCA, Status: "fixed"}},
		}
		changes := m.ReconcileTool(ReconcileContext{
			Tool:       ToolSCA,
			CurrentIDs: map[string]bool{"CVE-1": true},
		})
		if len(changes) != 1 || changes[0].NewStatus != "under_investigation" {
			t.Fatalf("got %+v", changes)
		}
	})

	t.Run("inventory tools return to inventory", func(t *testing.T) {
		m := &Memory{
			Version:  "1",
			Findings: map[string]FindingRecord{"CBOM:asset:SHA-1:hash": {Tool: ToolCBOM, Status: "fixed"}},
		}
		changes := m.ReconcileTool(ReconcileContext{
			Tool:             ToolCBOM,
			CurrentIDs:       map[string]bool{"CBOM:asset:SHA-1:hash": true},
			RegressionStatus: StatusInventory,
		})
		if len(changes) != 1 || changes[0].NewStatus != StatusInventory {
			t.Fatalf("got %+v", changes)
		}
		if m.Findings["CBOM:asset:SHA-1:hash"].Status != StatusInventory {
			t.Error("re-detected inventory should return to inventory, not to the triage queue")
		}
	})
}

// A detection pass the user disabled must not resolve the findings it would
// have produced: `cbom --no-certs` sees no certificates, which is not the same
// as the certificates having been deleted.
func TestReconcileTool_IDPrefixScope(t *testing.T) {
	m := &Memory{
		Version: "1",
		Findings: map[string]FindingRecord{
			"CBOM:asset:SHA-1:hash": {Tool: ToolCBOM, Status: "affected"},
			"CBOM:cert:cn=a:cn=b:z": {Tool: ToolCBOM, Status: StatusInventory},
		},
	}
	changes := m.ReconcileTool(ReconcileContext{
		Tool:       ToolCBOM,
		CurrentIDs: map[string]bool{},
		IDPrefixes: []string{"CBOM:asset:"},
	})
	if len(changes) != 1 || changes[0].CveID != "CBOM:asset:SHA-1:hash" {
		t.Fatalf("expected only the asset to resolve, got %+v", changes)
	}
	if m.Findings["CBOM:cert:cn=a:cn=b:z"].Status != StatusInventory {
		t.Error("out-of-scope certificate record must be left untouched")
	}
}

func TestReconcileTool_TerminalStatusesUntouched(t *testing.T) {
	m := &Memory{
		Version: "1",
		Findings: map[string]FindingRecord{
			"CVE-1": {Tool: ToolSCA, Status: "fixed"},
			"CVE-2": {Tool: ToolSCA, Status: "not_affected"},
		},
	}
	if changes := m.ReconcileTool(ReconcileContext{
		Tool:       ToolSCA,
		CurrentIDs: map[string]bool{},
	}); len(changes) != 0 {
		t.Fatalf("terminal records must not be re-resolved, got %+v", changes)
	}
}

func TestReconcileTool_SCAAbsenceComment(t *testing.T) {
	cases := []struct {
		name          string
		installedPkgs map[string]bool
		want          string
	}{
		{"no package inventory", nil, "No longer reported by upstream source"},
		{"dependency removed", map[string]bool{"npm:other": true}, "Dependency removed from manifest"},
		{"patched upstream", map[string]bool{"npm:lodash": true}, "Package still present but no longer flagged — patched upstream"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &Memory{
				Version: "1",
				Findings: map[string]FindingRecord{
					"CVE-1": {Tool: ToolSCA, Status: "affected", Package: "lodash", Ecosystem: "npm"},
				},
			}
			changes := m.ReconcileTool(ReconcileContext{
				Tool:          ToolSCA,
				CurrentIDs:    map[string]bool{},
				InstalledPkgs: tc.installedPkgs,
			})
			if len(changes) != 1 {
				t.Fatalf("expected 1 change, got %d", len(changes))
			}
			if changes[0].Comment != tc.want {
				t.Errorf("comment = %q, want %q", changes[0].Comment, tc.want)
			}
		})
	}
}

// StatusInventory is deliberately outside the "open" set so a CBOM/AIBOM
// inventory never lands in the triage queue, yet it is not terminal either.
func TestStatusInventory_NotOpenButResolvable(t *testing.T) {
	m := &Memory{
		Version: "1",
		Findings: map[string]FindingRecord{
			"AIBOM:library:openai": {Tool: ToolAIBOM, Status: StatusInventory},
		},
	}
	if len(m.GetOpenFindings()) != 0 {
		t.Error("inventory records must not appear in the open-findings queue")
	}
	if len(m.GetOpenFindingsByTools([]string{ToolAIBOM})) != 0 {
		t.Error("inventory records must not appear in tool-filtered open findings")
	}
	changes := m.ReconcileTool(ReconcileContext{Tool: ToolAIBOM, CurrentIDs: map[string]bool{}})
	if len(changes) != 1 || changes[0].NewStatus != "fixed" {
		t.Fatalf("inventory must still auto-resolve on absence, got %+v", changes)
	}
}

func TestRecordCategorizedFindings_InventoryEscalates(t *testing.T) {
	m := &Memory{Version: "1"}
	m.RecordCategorizedFindings(ToolCBOM, map[string]FindingRecord{
		"CBOM:asset:RSA:signature": {Status: StatusInventory, Locations: []Location{{File: "a.go"}}},
	})
	// The catalog now classifies the algorithm as quantum-vulnerable.
	m.RecordCategorizedFindings(ToolCBOM, map[string]FindingRecord{
		"CBOM:asset:RSA:signature": {Status: "affected", Locations: []Location{{File: "a.go"}}},
	})
	if got := m.Findings["CBOM:asset:RSA:signature"].Status; got != "affected" {
		t.Errorf("status = %q, want affected — inventory is not a triage decision worth preserving", got)
	}
}

func TestRecordCategorizedFindings_TriageDecisionPreserved(t *testing.T) {
	m := &Memory{Version: "1"}
	m.RecordCategorizedFindings(ToolSecrets, map[string]FindingRecord{
		"fp": {Status: "affected", Locations: []Location{{File: "a.go"}}},
	})
	rec := m.Findings["fp"]
	rec.Status = "not_affected"
	rec.Justification = "test fixture, not a real credential"
	m.Findings["fp"] = rec

	m.RecordCategorizedFindings(ToolSecrets, map[string]FindingRecord{
		"fp": {Status: "affected", Locations: []Location{{File: "a.go"}}},
	})
	got := m.Findings["fp"]
	if got.Status != "not_affected" || got.Justification == "" {
		t.Errorf("a user triage decision must survive a rescan, got %+v", got)
	}
}

func TestAppendHistory_CapsGrowth(t *testing.T) {
	var h []HistoryEntry
	for i := 0; i < maxFindingHistory+25; i++ {
		h = appendHistory(h, HistoryEntry{Date: "2026-01-01T00:00:00Z", Event: "scan"})
	}
	if len(h) != maxFindingHistory {
		t.Fatalf("history length = %d, want %d", len(h), maxFindingHistory)
	}
}

func TestAppendHistory_KeepsMostRecent(t *testing.T) {
	var h []HistoryEntry
	for i := 0; i < maxFindingHistory+1; i++ {
		h = appendHistory(h, HistoryEntry{Event: "scan", Detail: string(rune('a' + i%26))})
	}
	last := h[len(h)-1]
	if last.Detail != string(rune('a'+(maxFindingHistory)%26)) {
		t.Errorf("newest entry was dropped: %+v", last)
	}
}

func TestNormalizeTools_LicenseFromSource(t *testing.T) {
	m := &Memory{
		Findings: map[string]FindingRecord{
			"LICENSE-NOT-OSI-001": {Tool: "", Source: "vulnetix-license-analyzer"},
		},
	}
	normalizeTools(m)
	if got := m.Findings["LICENSE-NOT-OSI-001"].Tool; got != ToolLicense {
		t.Errorf("tool = %q, want %q", got, ToolLicense)
	}
}
