package memory

import (
	"os"
	"path/filepath"
	"testing"
)

func tmpVulnetixDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), ".vulnetix")
	if err := os.MkdirAll(d, 0755); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestSaveAndLoad(t *testing.T) {
	dir := tmpVulnetixDir(t)

	m := &Memory{
		Version: "1",
		Findings: map[string]FindingRecord{
			"CVE-2024-0001": {
				Package:   "test-pkg",
				Ecosystem: "npm",
				Status:    "affected",
			},
		},
	}

	if err := Save(dir, m); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.Version != "1" {
		t.Errorf("expected version '1', got %q", loaded.Version)
	}
	if rec, ok := loaded.Findings["CVE-2024-0001"]; !ok {
		t.Fatal("expected finding record for CVE-2024-0001")
	} else if rec.Package != "test-pkg" {
		t.Errorf("expected package 'test-pkg', got %q", rec.Package)
	}
}

func TestLoad_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	m, err := Load(dir)
	if err != nil {
		t.Fatalf("Load should return empty Memory, not error: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil empty Memory")
	}
	if m.Version == "" {
		t.Errorf("expected non-empty version")
	}
}

func TestSetScanContext(t *testing.T) {
	m := &Memory{}
	ctx := &ScanContext{Branch: "main", Path: "/app", Timestamp: "2024-01-01T00:00:00Z"}
	m.SetScanContext(ctx)
	if m.scanCtx.Branch != "main" {
		t.Errorf("expected branch 'main', got %q", m.scanCtx.Branch)
	}

	m.SetScanContext(nil)
	if m.scanCtx != nil {
		t.Error("expected nil after clearing")
	}
}

func TestRecordScan(t *testing.T) {
	m := &Memory{}
	m.RecordScan(ScanRecord{
		Path:      "/app",
		Timestamp: "2024-01-01T00:00:00Z",
	})

	if m.LastScan == nil {
		t.Fatal("expected LastScan to be set")
	}
	if m.LastScan.Path != "/app" {
		t.Errorf("expected path '/app', got %q", m.LastScan.Path)
	}
	if len(m.History) != 1 {
		t.Errorf("expected 1 history entry, got %d", len(m.History))
	}
}

func TestRecordVDBQuery(t *testing.T) {
	m := &Memory{}
	for i := 0; i < 5; i++ {
		m.RecordVDBQuery(VDBQuery{Command: "vuln", Timestamp: "2024-01-01T00:00:00Z"})
	}
	if len(m.VDBQueries) != 5 {
		t.Errorf("expected 5 queries, got %d", len(m.VDBQueries))
	}
}

func TestGetFinding(t *testing.T) {
	m := &Memory{
		Findings: map[string]FindingRecord{
			"CVE-2024-0001": {
				Package: "test-pkg",
				Status:  "affected",
			},
		},
	}

	f := m.GetFinding("CVE-2024-0001")
	if f == nil {
		t.Fatal("expected finding for CVE-2024-0001")
	}
	if f.Package != "test-pkg" {
		t.Errorf("expected 'test-pkg', got %q", f.Package)
	}

	f2 := m.GetFinding("nonexistent")
	if f2 != nil {
		t.Error("expected nil for nonexistent finding")
	}
}

func TestSetFinding(t *testing.T) {
	m := &Memory{Findings: map[string]FindingRecord{}}
	m.SetFinding("CVE-2024-0001", FindingRecord{
		Package: "new-pkg",
		Status:  "under_investigation",
	})

	rec := m.Findings["CVE-2024-0001"]
	if rec.Package != "new-pkg" {
		t.Errorf("expected 'new-pkg', got %q", rec.Package)
	}
	if rec.Status != "under_investigation" {
		t.Errorf("expected 'under_investigation', got %q", rec.Status)
	}
}

func TestGetOpenFindings(t *testing.T) {
	m := &Memory{
		Findings: map[string]FindingRecord{
			"CVE-2024-0001": {Status: "affected"},
			"CVE-2024-0002": {Status: "fixed"},
			"CVE-2024-0003": {Status: "under_investigation"},
		},
	}

	open := m.GetOpenFindings()
	if len(open) != 2 {
		t.Errorf("expected 2 open findings (affected+under_investigation), got %d", len(open))
	}
	if _, ok := open["CVE-2024-0002"]; ok {
		t.Error("fixed finding should not be in open list")
	}
}

func TestGetOpenFindingsByTools(t *testing.T) {
	m := &Memory{
		Findings: map[string]FindingRecord{
			"CVE-2024-0001": {Status: "affected", Tool: ToolSCA},
			"CVE-2024-0002": {Status: "affected", Tool: ToolSAST},
			"CVE-2024-0003": {Status: "affected", Tool: ToolIaC},
		},
	}

	sca := m.GetOpenFindingsByTools([]string{ToolSCA})
	if len(sca) != 1 {
		t.Errorf("expected 1 SCA finding, got %d", len(sca))
	}

	all := m.GetOpenFindingsByTools([]string{ToolSCA, ToolSAST, ToolIaC})
	if len(all) != 3 {
		t.Errorf("expected 3 findings, got %d", len(all))
	}
}

func TestToolSet(t *testing.T) {
	s := toolSet([]string{"a", "b", "c"})
	if len(s) != 3 {
		t.Errorf("expected 3, got %d", len(s))
	}
	if !s["a"] || !s["b"] || !s["c"] {
		t.Error("expected all keys present")
	}
}

func TestRecordSASTFindings(t *testing.T) {
	m := &Memory{}

	m.RecordSASTFindings([]SASTFindingRecord{
		{Fingerprint: "fp1", RuleID: "rule-1", ArtifactURI: "main.go", StartLine: 10},
	})

	if rec, ok := m.SASTFindings["fp1"]; !ok {
		t.Fatal("expected SAST finding for fp1")
	} else if rec.RuleID != "rule-1" {
		t.Errorf("expected rule-1, got %q", rec.RuleID)
	}
}

func TestRecordSASTFindings_Upsert(t *testing.T) {
	m := &Memory{
		SASTFindings: map[string]SASTFindingRecord{
			"fp1": {Fingerprint: "fp1", RuleID: "rule-1", Status: "resolved", ResolvedAt: "2024-01-01T00:00:00Z"},
		},
	}

	m.RecordSASTFindings([]SASTFindingRecord{
		{Fingerprint: "fp1", RuleID: "rule-1", ArtifactURI: "main.go", StartLine: 10},
	})

	rec := m.SASTFindings["fp1"]
	if rec.Status != "open" {
		t.Errorf("expected status 'open' on rescan, got %q", rec.Status)
	}
	if rec.ResolvedAt != "" {
		t.Errorf("expected empty ResolvedAt on rescan, got %q", rec.ResolvedAt)
	}
}

func TestMarkSASTFindingResolved(t *testing.T) {
	m := &Memory{
		SASTFindings: map[string]SASTFindingRecord{
			"fp1": {Fingerprint: "fp1", Status: "open"},
		},
	}

	m.MarkSASTFindingResolved("fp1")
	if m.SASTFindings["fp1"].Status != "resolved" {
		t.Errorf("expected 'resolved', got %q", m.SASTFindings["fp1"].Status)
	}

	m.MarkSASTFindingResolved("nonexistent")
}

func TestGetOpenSASTFindingsByTools(t *testing.T) {
	m := &Memory{
		SASTFindings: map[string]SASTFindingRecord{
			"fp1": {Fingerprint: "fp1", Status: "open", Tool: ToolSAST},
			"fp2": {Fingerprint: "fp2", Status: "resolved", Tool: ToolSAST},
			"fp3": {Fingerprint: "fp3", Status: "open", Tool: ToolIaC},
		},
	}

	sast := m.GetOpenSASTFindingsByTools([]string{ToolSAST})
	if len(sast) != 1 {
		t.Errorf("expected 1 open SAST finding, got %d", len(sast))
	}

	none := m.GetOpenSASTFindingsByTools([]string{ToolLicense})
	if len(none) != 0 {
		t.Errorf("expected 0 license findings, got %d", len(none))
	}

	// Test fallback: empty Tool defaults to ToolSAST
	m2 := &Memory{
		SASTFindings: map[string]SASTFindingRecord{
			"fp1": {Fingerprint: "fp1", Status: "open", Tool: ""},
		},
	}
	result := m2.GetOpenSASTFindingsByTools([]string{ToolSAST})
	if len(result) != 1 {
		t.Errorf("expected 1 finding when tool is empty (falls back to SAST), got %d", len(result))
	}
}

func TestReconcileFindings_FixedAndRegression(t *testing.T) {
	m := &Memory{
		Findings: map[string]FindingRecord{
			"CVE-2024-0001": {
				Package: "pkg-a",
				Source:  "vulnetix-sca",
				Status:  "affected",
			},
			"CVE-2024-0002": {
				Package: "pkg-b",
				Source:  "vulnetix-sca",
				Status:  "fixed",
			},
		},
	}

	current := map[string]bool{"CVE-2024-0002": true}
	changes := m.ReconcileFindings(current)

	if len(changes) != 2 {
		t.Fatalf("expected 2 changes, got %d", len(changes))
	}

	foundFixed := false
	foundRegression := false
	for _, c := range changes {
		if c.CveID == "CVE-2024-0001" && c.NewStatus == "fixed" {
			foundFixed = true
		}
		if c.CveID == "CVE-2024-0002" && c.NewStatus == "under_investigation" {
			foundRegression = true
		}
	}
	if !foundFixed {
		t.Error("expected CVE-2024-0001 to be marked fixed")
	}
	if !foundRegression {
		t.Error("expected CVE-2024-0002 to be regression")
	}
}

func TestReconcileFindings_NonSCASkipped(t *testing.T) {
	m := &Memory{
		Findings: map[string]FindingRecord{
			"CVE-2024-0001": {
				Source: "manual",
				Status: "affected",
			},
		},
	}

	changes := m.ReconcileFindings(map[string]bool{})
	if len(changes) != 0 {
		t.Errorf("expected 0 changes for non-SCA source, got %d", len(changes))
	}
}

func TestRecordCategorizedFindings(t *testing.T) {
	m := &Memory{Findings: map[string]FindingRecord{}}

	m.RecordCategorizedFindings(ToolSCA, map[string]FindingRecord{
		"CVE-2024-0001": {
			Package: "pkg-a",
			Status:  "affected",
		},
	})

	if len(m.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(m.Findings))
	}
	if m.Findings["CVE-2024-0001"].Tool != ToolSCA {
		t.Errorf("expected Tool='%s', got '%s'", ToolSCA, m.Findings["CVE-2024-0001"].Tool)
	}
}

func TestUpdateEnvironment(t *testing.T) {
	m := &Memory{}
	env := &EnvironmentContext{Platform: "test-platform"}
	m.UpdateEnvironment(env)
	if m.Environment == nil || m.Environment.Platform != "test-platform" {
		t.Errorf("expected platform 'test-platform', got %v", m.Environment)
	}
}

func TestRecordEnrichedFindings(t *testing.T) {
	m := &Memory{Findings: map[string]FindingRecord{}}

	m.RecordEnrichedFindings([]EnrichedFinding{
		{
			CveID:       "CVE-2024-0001",
			PackageName: "pkg-a",
			Ecosystem:   "npm",
			MaxSeverity: "high",
			CVSSScore:   8.5,
			EPSSScore:   0.05,
		},
	})

	rec := m.Findings["CVE-2024-0001"]
	if rec.Package != "pkg-a" {
		t.Errorf("expected 'pkg-a', got %q", rec.Package)
	}
	if rec.Severity != "high" {
		t.Errorf("expected 'high', got %q", rec.Severity)
	}
}

func TestRecordVulnLookup(t *testing.T) {
	m := &Memory{Findings: map[string]FindingRecord{}}
	m.RecordVulnLookup("CVE-2024-0001", map[string]interface{}{
		"id": "CVE-2024-0001",
	})
}

func TestRecordReachability(t *testing.T) {
	m := &Memory{Findings: map[string]FindingRecord{}}

	ev := &ReachabilityEvidence{
		Direct: []ReachabilityMatch{
			{File: "main.go", Range: "10:15", Query: "test-query"},
		},
	}

	m.RecordReachability("CVE-2024-0001", ev)
}

func TestReachabilitySummary(t *testing.T) {
	ev := &ReachabilityEvidence{
		Direct:     []ReachabilityMatch{{File: "a.go", Range: "1:5"}},
		Transitive: []ReachabilityMatch{{File: "b.go", Range: "10:15"}},
	}
	summary := reachabilitySummary(ev)
	if summary != "1 direct, 1 transitive" {
		t.Errorf("unexpected summary: %q", summary)
	}

	empty := &ReachabilityEvidence{}
	s2 := reachabilitySummary(empty)
	if s2 != "0 direct, 0 transitive" {
		t.Errorf("expected '0 direct, 0 transitive', got %q", s2)
	}

	sNil := reachabilitySummary(nil)
	if sNil != "no matches" {
		t.Errorf("expected 'no matches' for nil, got %q", sNil)
	}
}

func TestExtractVulnMap(t *testing.T) {
	m := extractVulnMap(map[string]interface{}{"id": "CVE-0001"})
	if m == nil {
		t.Fatal("expected non-nil map")
	}

	arr := extractVulnMap([]interface{}{map[string]interface{}{"id": "CVE-0002"}})
	if arr == nil {
		t.Fatal("expected non-nil from array")
	}

	empty := extractVulnMap([]interface{}{})
	if empty != nil {
		t.Error("expected nil for empty array")
	}

	nilR := extractVulnMap(nil)
	if nilR != nil {
		t.Error("expected nil for nil input")
	}

	nonMap := extractVulnMap("string")
	if nonMap != nil {
		t.Error("expected nil for string input")
	}
}

func TestExtractString(t *testing.T) {
	m := map[string]interface{}{"key": "value", "num": 42}
	v, ok := extractString(m, "key")
	if !ok || v != "value" {
		t.Errorf("expected 'value', got %q (ok=%v)", v, ok)
	}
	_, ok = extractString(m, "missing")
	if ok {
		t.Error("expected false for missing key")
	}
	_, ok = extractString(m, "num")
	if ok {
		t.Error("expected false for non-string value")
	}
}

func TestExtractFloat(t *testing.T) {
	m := map[string]interface{}{"f": 3.14, "i": 42, "s": "nope"}
	v, ok := extractFloat(m, "f")
	if !ok || v != 3.14 {
		t.Errorf("expected 3.14, got %f (ok=%v)", v, ok)
	}
	v2, ok2 := extractFloat(m, "i")
	if !ok2 || v2 != 42.0 {
		t.Errorf("expected 42.0, got %f", v2)
	}
	_, ok3 := extractFloat(m, "s")
	if ok3 {
		t.Error("expected false for string")
	}
	_, ok4 := extractFloat(m, "missing")
	if ok4 {
		t.Error("expected false for missing")
	}
}

func TestExtractStringSlice(t *testing.T) {
	m := map[string]interface{}{
		"items": []interface{}{"a", "b", "c"},
		"mixed": []interface{}{"a", 1, "c"},
		"empty": []interface{}{},
	}
	result, ok := extractStringSlice(m, "items")
	if !ok || len(result) != 3 {
		t.Errorf("expected 3 items, got %d (ok=%v)", len(result), ok)
	}
	result2, _ := extractStringSlice(m, "mixed")
	if len(result2) != 2 {
		t.Errorf("expected 2 string items, got %d", len(result2))
	}
	_, ok3 := extractStringSlice(m, "empty")
	if ok3 {
		t.Error("expected false for empty slice")
	}
	_, ok4 := extractStringSlice(m, "missing")
	if ok4 {
		t.Error("expected false for missing key")
	}
}

func TestAllTools(t *testing.T) {
	want := []string{
		ToolSCA, ToolSAST, ToolIaC, ToolSecrets, ToolContainer,
		ToolQuality, ToolLicense, ToolCBOM, ToolAIBOM, ToolMalscan,
	}
	seen := map[string]bool{}
	for _, tool := range AllTools {
		if seen[tool] {
			t.Errorf("duplicate tool tag %q in AllTools", tool)
		}
		seen[tool] = true
	}
	for _, tool := range want {
		if !seen[tool] {
			t.Errorf("tool tag %q missing from AllTools", tool)
		}
	}
	if len(AllTools) != len(want) {
		t.Errorf("AllTools has %d entries, want %d", len(AllTools), len(want))
	}
}

func TestNormalizeTools_SCAFindingsBySource(t *testing.T) {
	m := &Memory{
		Findings: map[string]FindingRecord{
			"CVE-0001": {Tool: "", Source: "vulnetix-sca"},
			"CVE-0002": {Tool: "", Source: "github"},
			"CVE-0003": {Tool: "", Source: "dependabot"},
		},
	}
	normalizeTools(m)

	if m.Findings["CVE-0001"].Tool != ToolSCA {
		t.Errorf("vulnetix-sca should normalize to '%s', got '%s'", ToolSCA, m.Findings["CVE-0001"].Tool)
	}
	if m.Findings["CVE-0002"].Tool != ToolSCA {
		t.Errorf("github should normalize to '%s', got '%s'", ToolSCA, m.Findings["CVE-0002"].Tool)
	}
	if m.Findings["CVE-0003"].Tool != ToolSCA {
		t.Errorf("dependabot should normalize to '%s', got '%s'", ToolSCA, m.Findings["CVE-0003"].Tool)
	}
}

func TestNormalizeTools_SASTFindingsAlwaysSAST(t *testing.T) {
	m := &Memory{
		SASTFindings: map[string]SASTFindingRecord{
			"fp1": {Fingerprint: "fp1", RuleID: "r1", Tool: ""},
		},
	}
	normalizeTools(m)

	if m.SASTFindings["fp1"].Tool != ToolSAST {
		t.Errorf("SAST finding should always normalize to '%s', got '%s'", ToolSAST, m.SASTFindings["fp1"].Tool)
	}
}

func TestNormalizeTools_AlreadySetUnchanged(t *testing.T) {
	m := &Memory{
		Findings: map[string]FindingRecord{
			"CVE-0001": {Tool: ToolIaC, Source: "vulnetix-sca"},
		},
	}
	normalizeTools(m)
	if m.Findings["CVE-0001"].Tool != ToolIaC {
		t.Errorf("already-set Tool should not change, got '%s'", m.Findings["CVE-0001"].Tool)
	}
}

func TestStampSeen_WithContext(t *testing.T) {
	m := &Memory{
		scanCtx: &ScanContext{Branch: "main", Path: "/app"},
	}

	branch, ts := m.stampSeen("2024-01-01T00:00:00Z")
	if branch != "main" {
		t.Errorf("expected branch 'main', got %q", branch)
	}
	if ts != "2024-01-01T00:00:00Z" {
		t.Errorf("expected ts, got %q", ts)
	}
}

func TestStampSeen_ContextWithTimestamp(t *testing.T) {
	m := &Memory{
		scanCtx: &ScanContext{Branch: "main", Path: "/app", Timestamp: "from-context"},
	}

	branch, ts := m.stampSeen("ignored")
	if branch != "main" {
		t.Errorf("expected branch 'main', got %q", branch)
	}
	if ts != "from-context" {
		t.Errorf("expected 'from-context' from context, got %q", ts)
	}
}

func TestStampSeen_NoContext(t *testing.T) {
	m := &Memory{}
	branch, ts := m.stampSeen("")
	if branch != "" {
		t.Errorf("expected empty branch, got %q", branch)
	}
	if ts != "" {
		t.Errorf("expected empty ts when both now and context are empty, got %q", ts)
	}
}
