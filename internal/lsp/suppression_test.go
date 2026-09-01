package lsp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/vulnetix/cli/v3/internal/lsp/protocol"
	"github.com/vulnetix/cli/v3/internal/memory"
)

// writeMemory puts a memory.yaml with the given suppressions in a temp repo.
func writeMemory(t *testing.T, records []memory.SuppressionRecord) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, vulnetixDirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	mem := &memory.Memory{Suppressions: records}
	if err := memory.Save(dir, mem); err != nil {
		t.Fatal(err)
	}
	return root
}

func diagWithData(source, code string, data DiagnosticData) protocol.Diagnostic {
	raw, _ := json.Marshal(data)
	return protocol.Diagnostic{
		Source:   source,
		Code:     code,
		Message:  "finding",
		Severity: protocol.SeverityError,
		Data:     raw,
	}
}

// The shared matcher is used by every scan pipeline, so a rule that hides a
// finding in CI has to hide it in the editor too — for code findings as much as
// for dependency ones.
func TestMemorySuppressionsHideBothFamilies(t *testing.T) {
	root := writeMemory(t, []memory.SuppressionRecord{
		{RuleID: "VNX-JS-001", IsActive: true, Reason: "false positive"},
		{FindingID: "CVE-2021-23337", IsActive: true, Reason: "not reachable"},
	})

	store := newSuppressionStore()
	store.Reload(root, DefaultSettings())

	diags := []protocol.Diagnostic{
		diagWithData("vulnetix-sast", "VNX-JS-001", DiagnosticData{FindingID: "abc"}),
		diagWithData("vulnetix-sast", "VNX-JS-002", DiagnosticData{FindingID: "def"}),
		diagWithData(SourceSCA, "CVE-2021-23337", DiagnosticData{
			SCA: &scaDiagnosticData{CveIDs: []string{"CVE-2021-23337"}},
		}),
		diagWithData(SourceSCA, "CVE-2020-7598", DiagnosticData{
			SCA: &scaDiagnosticData{CveIDs: []string{"CVE-2020-7598"}},
		}),
	}

	got := store.Filter("src/app.js", diags, false)
	if len(got) != 2 {
		t.Fatalf("got %d diagnostics, want 2 unsuppressed", len(got))
	}
	if got[0].Code != "VNX-JS-002" || got[1].Code != "CVE-2020-7598" {
		t.Errorf("wrong diagnostics survived: %q, %q", got[0].Code, got[1].Code)
	}
}

// The editor-level rule exists so someone can silence a finding without
// committing a change to the file the whole team shares.
func TestExtensionSuppressionsApplyOverTheMemoryFile(t *testing.T) {
	root := writeMemory(t, []memory.SuppressionRecord{
		{RuleID: "VNX-JS-001", IsActive: true},
	})

	cfg := DefaultSettings()
	cfg.Suppressions = []SuppressionSetting{
		{FindingID: "CVE-2020-7598", Reason: "accepted locally"},
	}

	store := newSuppressionStore()
	store.Reload(root, cfg)

	diags := []protocol.Diagnostic{
		diagWithData("vulnetix-sast", "VNX-JS-001", DiagnosticData{}),
		diagWithData(SourceSCA, "CVE-2020-7598", DiagnosticData{
			SCA: &scaDiagnosticData{CveIDs: []string{"CVE-2020-7598"}},
		}),
		diagWithData(SourceSCA, "CVE-2021-23337", DiagnosticData{
			SCA: &scaDiagnosticData{CveIDs: []string{"CVE-2021-23337"}},
		}),
	}

	got := store.Filter("src/app.js", diags, false)
	if len(got) != 1 || got[0].Code != "CVE-2021-23337" {
		t.Fatalf("got %d diagnostics, want only CVE-2021-23337: %+v", len(got), got)
	}
}

// Showing suppressed findings demotes them rather than dropping them: a Hint
// stays visible in the file while staying out of the error counts.
func TestShowSuppressedDemotesInsteadOfHiding(t *testing.T) {
	root := writeMemory(t, []memory.SuppressionRecord{
		{RuleID: "VNX-JS-001", IsActive: true, Reason: "reviewed"},
	})

	store := newSuppressionStore()
	store.Reload(root, DefaultSettings())

	diags := []protocol.Diagnostic{diagWithData("vulnetix-sast", "VNX-JS-001", DiagnosticData{})}

	got := store.Filter("src/app.js", diags, true)
	if len(got) != 1 {
		t.Fatalf("got %d diagnostics, want the demoted one", len(got))
	}
	if got[0].Severity != protocol.SeverityHint {
		t.Errorf("severity = %d, want Hint", got[0].Severity)
	}
	if got[0].Message == "finding" {
		t.Error("the message should say the finding was suppressed and why")
	}
}

// An inactive or expired rule must not silence anything.
func TestInactiveSuppressionsAreIgnored(t *testing.T) {
	root := writeMemory(t, []memory.SuppressionRecord{
		{RuleID: "VNX-JS-001", IsActive: false},
		{RuleID: "VNX-JS-002", IsActive: true, ExpiresAt: 1},
	})

	store := newSuppressionStore()
	store.Reload(root, DefaultSettings())

	diags := []protocol.Diagnostic{
		diagWithData("vulnetix-sast", "VNX-JS-001", DiagnosticData{}),
		diagWithData("vulnetix-sast", "VNX-JS-002", DiagnosticData{}),
	}
	if got := store.Filter("src/app.js", diags, false); len(got) != 2 {
		t.Errorf("got %d diagnostics, want both", len(got))
	}
}

// Most repositories have no memory file. That must leave suppression working
// off the editor's own rules rather than failing.
func TestMissingMemoryFileIsNotAnError(t *testing.T) {
	root := t.TempDir()

	cfg := DefaultSettings()
	cfg.Suppressions = []SuppressionSetting{{RuleID: "VNX-JS-001"}}

	store := newSuppressionStore()
	store.Reload(root, cfg)

	diags := []protocol.Diagnostic{
		diagWithData("vulnetix-sast", "VNX-JS-001", DiagnosticData{}),
		diagWithData("vulnetix-sast", "VNX-JS-002", DiagnosticData{}),
	}
	got := store.Filter("src/app.js", diags, false)
	if len(got) != 1 || got[0].Code != "VNX-JS-002" {
		t.Errorf("editor rules should still apply without a memory file: %+v", got)
	}
}

// The setting names a location a user would plausibly type: either the
// directory or the file inside it.
func TestMemoryDirAcceptsEitherForm(t *testing.T) {
	cases := map[string]string{
		"":                       filepath.Join("/repo", ".vulnetix"),
		".vulnetix":              filepath.Join("/repo", ".vulnetix"),
		".vulnetix/memory.yaml":  filepath.Join("/repo", ".vulnetix"),
		"config/vulnetix":        filepath.Join("/repo", "config", "vulnetix"),
		"/abs/state":             "/abs/state",
		"/abs/state/memory.yaml": "/abs/state",
	}
	for configured, want := range cases {
		if got := memoryDir("/repo", configured); got != want {
			t.Errorf("memoryDir(%q) = %q, want %q", configured, got, want)
		}
	}
}

func TestCategoryOfMapsEveryFamily(t *testing.T) {
	cases := map[string]string{
		SourceSCA:             "sca",
		"vulnetix-sast":       "sast",
		"vulnetix-secrets":    "secrets",
		"vulnetix-iac":        "iac",
		"vulnetix-containers": "oci",
		"vulnetix-license":    "license",
		"vulnetix-malware":    "malware",
		"something-else":      "sast",
	}
	for source, want := range cases {
		if got := categoryOf(source); got != want {
			t.Errorf("categoryOf(%q) = %q, want %q", source, got, want)
		}
	}
}
