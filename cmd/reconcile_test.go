package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	cyclonedx "github.com/Vulnetix/vdb-cyclonedx"
	"github.com/vulnetix/cli/v3/internal/license"
	"github.com/vulnetix/cli/v3/internal/memory"
)

// withMemoryEnabled restores the global --disable-memory flag after the test.
func withMemoryEnabled(t *testing.T) {
	t.Helper()
	prev := disableMemory
	disableMemory = false
	t.Cleanup(func() { disableMemory = prev })
}

func readMemory(t *testing.T, root string) *memory.Memory {
	t.Helper()
	mem, err := memory.Load(filepath.Join(root, ".vulnetix"))
	if err != nil {
		t.Fatalf("load memory: %v", err)
	}
	return mem
}

func TestVulnetixDirFor(t *testing.T) {
	if got := vulnetixDirFor(""); got != filepath.Join(".", ".vulnetix") {
		t.Errorf("empty root: got %q", got)
	}
	if got := vulnetixDirFor("/tmp/proj"); got != "/tmp/proj/.vulnetix" {
		t.Errorf("explicit root: got %q", got)
	}
}

// Memory belongs to the tree being scanned, not to the process working
// directory. A --path pointing elsewhere must write there and nowhere else.
func TestReconcileStandalone_WritesMemoryUnderScanRoot(t *testing.T) {
	withMemoryEnabled(t)
	root := t.TempDir()
	// Put the process somewhere else entirely: --path, not the working
	// directory, decides where memory lives.
	cwd := t.TempDir()
	t.Chdir(cwd)

	reconcileStandalone(root, nil, memory.ToolMalscan, map[string]memory.FindingRecord{
		"fp-1": {Aliases: []string{"IOC-STIX-MATCH"}, Severity: "critical", Status: "affected"},
	}, reconcileOptions{Mode: memory.ResolveOnAbsence})

	if _, err := os.Stat(filepath.Join(root, ".vulnetix", "memory.yaml")); err != nil {
		t.Fatalf("memory.yaml not written under the scan root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cwd, ".vulnetix")); err == nil {
		t.Error("memory leaked into the process working directory")
	}
}

// The whole point of the feature: a finding recorded on run 1 that the scanner
// no longer reports on run 2 becomes `fixed` and produces a VEX statement.
func TestReconcileStandalone_ResolvesDisappearedFinding(t *testing.T) {
	withMemoryEnabled(t)
	root := t.TempDir()

	current := map[string]memory.FindingRecord{
		"fp-1": {Aliases: []string{"IOC-STIX-MATCH"}, Severity: "critical", Status: "affected"},
	}
	if changes := reconcileStandalone(root, nil, memory.ToolMalscan, current,
		reconcileOptions{Mode: memory.ResolveOnAbsence}); len(changes) != 0 {
		t.Fatalf("first run should report no state changes, got %+v", changes)
	}
	if got := readMemory(t, root).Findings["fp-1"].Status; got != "affected" {
		t.Fatalf("after first run status = %q, want affected", got)
	}

	// Second run: the engine reports nothing.
	changes := reconcileStandalone(root, nil, memory.ToolMalscan,
		map[string]memory.FindingRecord{}, reconcileOptions{Mode: memory.ResolveOnAbsence})
	if len(changes) != 1 || changes[0].NewStatus != "fixed" {
		t.Fatalf("expected one resolution, got %+v", changes)
	}
	if got := readMemory(t, root).Findings["fp-1"].Status; got != "fixed" {
		t.Errorf("after clean rescan status = %q, want fixed", got)
	}

	vexPath, err := writeToolOpenVEX(root, memory.ToolMalscan, changes)
	if err != nil {
		t.Fatalf("writeToolOpenVEX: %v", err)
	}
	if vexPath != filepath.Join(root, ".vulnetix", "vex-malscan.openvex.json") {
		t.Fatalf("unexpected VEX path %q", vexPath)
	}
	data, err := os.ReadFile(vexPath)
	if err != nil {
		t.Fatalf("read VEX: %v", err)
	}
	var doc struct {
		Statements []struct {
			Status          string `json:"status"`
			Vulnerability   any    `json:"vulnerability"`
			ActionStatement string `json:"action_statement"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("VEX is not valid JSON: %v", err)
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("expected 1 VEX statement, got %d", len(doc.Statements))
	}
	if doc.Statements[0].Status != "fixed" {
		t.Errorf("VEX status = %q, want fixed", doc.Statements[0].Status)
	}
}

func TestWriteToolOpenVEX_NoChangesWritesNothing(t *testing.T) {
	root := t.TempDir()
	path, err := writeToolOpenVEX(root, memory.ToolCBOM, nil)
	if err != nil || path != "" {
		t.Fatalf("got (%q, %v), want (\"\", nil)", path, err)
	}
	if _, err := os.Stat(filepath.Join(root, ".vulnetix", "vex-cbom.openvex.json")); err == nil {
		t.Error("an empty change set must not leave a VEX artefact behind")
	}
}

// SCA and license attest through CycloneDX, so they own no OpenVEX artefact.
func TestWriteToolOpenVEX_CDXToolsHaveNoOpenVEXChannel(t *testing.T) {
	root := t.TempDir()
	for _, tool := range []string{memory.ToolSCA, memory.ToolLicense} {
		path, err := writeToolOpenVEX(root, tool, []memory.StateChange{
			{CveID: "CVE-1", Tool: tool, NewStatus: "fixed"},
		})
		if err != nil || path != "" {
			t.Errorf("%s: got (%q, %v), want (\"\", nil)", tool, path, err)
		}
	}
}

// The four static-analysis tools share vex.openvex.json. Writing them one at a
// time would leave only the last tool's statements on disk.
func TestWriteOpenVEXForPartition_MergesSharedArtefact(t *testing.T) {
	root := t.TempDir()
	paths := writeOpenVEXForPartition(root, map[string][]memory.StateChange{
		memory.ToolSAST:      {{CveID: "fp-sast", Tool: memory.ToolSAST, NewStatus: "fixed"}},
		memory.ToolSecrets:   {{CveID: "fp-secret", Tool: memory.ToolSecrets, NewStatus: "fixed"}},
		memory.ToolIaC:       {{CveID: "fp-iac", Tool: memory.ToolIaC, NewStatus: "fixed"}},
		memory.ToolContainer: {{CveID: "fp-oci", Tool: memory.ToolContainer, NewStatus: "fixed"}},
		memory.ToolCBOM:      {{CveID: "CBOM:asset:MD5:hash", Tool: memory.ToolCBOM, NewStatus: "fixed"}},
		memory.ToolSCA:       {{CveID: "CVE-1", Tool: memory.ToolSCA, NewStatus: "fixed"}},
	})
	if len(paths) != 2 {
		t.Fatalf("expected 2 artefacts (shared static-analysis + cbom), got %v", paths)
	}

	data, err := os.ReadFile(filepath.Join(root, ".vulnetix", "vex.openvex.json"))
	if err != nil {
		t.Fatalf("read shared VEX: %v", err)
	}
	var doc struct {
		Statements []json.RawMessage `json:"statements"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(doc.Statements) != 4 {
		t.Errorf("expected all 4 static-analysis statements in one document, got %d", len(doc.Statements))
	}
	if _, err := os.Stat(filepath.Join(root, ".vulnetix", "vex-cbom.openvex.json")); err != nil {
		t.Errorf("cbom VEX not written: %v", err)
	}
}

// Rule-based tools name their VEX statement after the rule (carried in Aliases);
// inventory tools have no rule, so the synthetic key is the identifier.
func TestWriteOpenVEXFile_VulnerabilityNaming(t *testing.T) {
	cases := []struct {
		name    string
		tool    string
		change  memory.StateChange
		wantVEX string
	}{
		{
			name: "malscan names the rule",
			tool: memory.ToolMalscan,
			change: memory.StateChange{
				CveID:   "9f2b1c",
				Tool:    memory.ToolMalscan,
				Finding: memory.FindingRecord{Aliases: []string{"IOC-STIX-MATCH"}},
			},
			wantVEX: "IOC-STIX-MATCH",
		},
		{
			name:    "cbom names the synthetic key",
			tool:    memory.ToolCBOM,
			change:  memory.StateChange{CveID: "CBOM:asset:sha-1:hash", Tool: memory.ToolCBOM},
			wantVEX: "CBOM:asset:sha-1:hash",
		},
		{
			name:    "aibom names the synthetic key",
			tool:    memory.ToolAIBOM,
			change:  memory.StateChange{CveID: "AIBOM:model:gpt-4o:openai-python", Tool: memory.ToolAIBOM},
			wantVEX: "AIBOM:model:gpt-4o:openai-python",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			tc.change.NewStatus = "fixed"
			path, err := writeToolOpenVEX(root, tc.tool, []memory.StateChange{tc.change})
			if err != nil {
				t.Fatalf("writeToolOpenVEX: %v", err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read VEX: %v", err)
			}
			var doc struct {
				Statements []struct {
					Vulnerability struct {
						Name string `json:"name"`
					} `json:"vulnerability"`
				} `json:"statements"`
			}
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}
			if len(doc.Statements) != 1 {
				t.Fatalf("expected 1 statement, got %d", len(doc.Statements))
			}
			if got := doc.Statements[0].Vulnerability.Name; got != tc.wantVEX {
				t.Errorf("vulnerability.name = %q, want %q", got, tc.wantVEX)
			}
		})
	}
}

func TestPartitionChangesByTool_UntaggedFallsBackToSCA(t *testing.T) {
	got := partitionChangesByTool([]memory.StateChange{
		{CveID: "CVE-1"},
		{CveID: "fp-1", Tool: memory.ToolSecrets},
	})
	if len(got[memory.ToolSCA]) != 1 || len(got[memory.ToolSecrets]) != 1 {
		t.Fatalf("unexpected partition: %+v", got)
	}
}

func TestCDXVEXForChanges(t *testing.T) {
	vulns := cdxVEXForChanges([]memory.StateChange{
		{CveID: "CVE-2", Tool: memory.ToolSCA, NewStatus: "fixed", Comment: "gone", Package: "lodash"},
		{CveID: "CVE-1", Tool: memory.ToolSCA, NewStatus: "under_investigation", Comment: "back"},
	}, "vulnetix-sca")
	if len(vulns) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(vulns))
	}
	// Sorted, so the BOM is byte-stable across runs.
	if vulns[0].ID != "CVE-1" || vulns[1].ID != "CVE-2" {
		t.Errorf("entries are not sorted by ID: %s, %s", vulns[0].ID, vulns[1].ID)
	}
	if vulns[1].Analysis == nil || vulns[1].Analysis.State != "resolved" {
		t.Errorf("fixed finding should map to CDX state 'resolved', got %+v", vulns[1].Analysis)
	}
	if vulns[0].Analysis == nil || vulns[0].Analysis.State != "in_triage" {
		t.Errorf("regressed finding should map to CDX state 'in_triage', got %+v", vulns[0].Analysis)
	}
}

func TestSeverityForPQC(t *testing.T) {
	cases := map[string][2]string{
		"quantum-vulnerable": {"high", "affected"},
		"deprecated":         {"medium", "affected"},
		"hybrid":             {"low", memory.StatusInventory},
		"quantum-safe":       {"info", memory.StatusInventory},
		"":                   {"info", memory.StatusInventory},
	}
	for pqc, want := range cases {
		sev, status := severityForPQC(pqc)
		if sev != want[0] || status != want[1] {
			t.Errorf("%q: got (%s, %s), want (%s, %s)", pqc, sev, status, want[0], want[1])
		}
	}
}

// ── license ──────────────────────────────────────────────────────────────────

func TestMigrateLegacyLicenseIDs(t *testing.T) {
	mem := &memory.Memory{
		Version: "1",
		Findings: map[string]memory.FindingRecord{
			"LICENSE-NOT-OSI-001": {
				Tool:      memory.ToolLicense,
				Package:   "some-pkg",
				Ecosystem: "npm",
				Status:    "not_affected",
				Versions:  &memory.VersionInfo{Current: "1.2.3"},
			},
			"LICENSE-CONFLICT-002": {
				Tool:   memory.ToolLicense,
				Source: license.CDXSourceName,
			},
			"CVE-2021-44228": {Tool: memory.ToolSCA},
		},
	}
	migrated, dropped := migrateLegacyLicenseIDs(mem)
	if migrated != 1 || dropped != 1 {
		t.Fatalf("migrated=%d dropped=%d, want 1/1", migrated, dropped)
	}

	newID := "LICENSE:not-osi-approved:npm:some-pkg@1.2.3"
	rec, ok := mem.Findings[newID]
	if !ok {
		t.Fatalf("record not re-keyed to %q; have %v", newID, mem.Findings)
	}
	if rec.Status != "not_affected" {
		t.Errorf("triage decision lost during migration: status = %q", rec.Status)
	}
	if _, stale := mem.Findings["LICENSE-NOT-OSI-001"]; stale {
		t.Error("legacy key still present")
	}
	if _, stale := mem.Findings["LICENSE-CONFLICT-002"]; stale {
		t.Error("unmigratable conflict record should have been dropped")
	}
	if _, ok := mem.Findings["CVE-2021-44228"]; !ok {
		t.Error("migration must not touch non-license records")
	}
}

func TestMigrateLegacyLicenseIDs_IsIdempotent(t *testing.T) {
	mem := &memory.Memory{
		Version: "1",
		Findings: map[string]memory.FindingRecord{
			"LICENSE:not-osi-approved:npm:some-pkg@1.2.3": {Tool: memory.ToolLicense, Package: "some-pkg"},
		},
	}
	if migrated, dropped := migrateLegacyLicenseIDs(mem); migrated != 0 || dropped != 0 {
		t.Fatalf("deterministic IDs must not be re-migrated: %d/%d", migrated, dropped)
	}
}

// license.MergeBOM strips every vulnerability carrying the license source before
// appending the new ones, so the VEX entry has to be re-derived from memory on
// every run. A helper reading only this run's state changes would emit the entry
// once and let the next run erase it.
func TestLicenseVEXFromMemory(t *testing.T) {
	mem := &memory.Memory{
		Version: "1",
		Findings: map[string]memory.FindingRecord{
			"LICENSE:unknown-license:npm:gone@1": {
				Tool: memory.ToolLicense, Status: "fixed", Package: "gone",
				History: []memory.HistoryEntry{
					{Event: "scan"},
					{Event: "auto-resolved", Detail: "Package or license condition no longer detected"},
				},
			},
			"LICENSE:unknown-license:npm:live@1": {Tool: memory.ToolLicense, Status: "affected"},
			"LICENSE:unknown-license:npm:back@1": {Tool: memory.ToolLicense, Status: "under_investigation"},
			"CVE-2021-44228":                     {Tool: memory.ToolSCA, Status: "fixed"},
		},
	}
	got := licenseVEXFromMemory(mem)
	if len(got) != 1 || got[0].ID != "LICENSE:unknown-license:npm:gone@1" {
		t.Fatalf("expected only the resolved license finding, got %+v", got)
	}
	if got[0].Source == nil || got[0].Source.Name != license.CDXSourceName {
		t.Errorf("license VEX must carry the license source name, got %+v", got[0].Source)
	}
	if got[0].Analysis == nil || got[0].Analysis.State != "resolved" {
		t.Fatalf("expected CDX state 'resolved', got %+v", got[0].Analysis)
	}
	if got[0].Analysis.Detail != "Package or license condition no longer detected" {
		t.Errorf("resolution detail should be recovered from history, got %q", got[0].Analysis.Detail)
	}
}

func TestAutoResolvedDetail_FallsBackWhenNoHistory(t *testing.T) {
	got := autoResolvedDetail(memory.FindingRecord{})
	if got == "" {
		t.Error("a hand-resolved record still needs a VEX detail")
	}
}

func TestLicenseFindingRecords(t *testing.T) {
	result := &license.AnalysisResult{
		Findings: []license.Finding{{
			ID:       "LICENSE:unknown-license:npm:a@1.0.0",
			Severity: "medium",
			Package: license.PackageLicense{
				PackageName: "a", PackageVersion: "1.0.0", Ecosystem: "npm", SourceFile: "package.json",
			},
		}},
	}
	recs := licenseFindingRecords(result)
	rec, ok := recs["LICENSE:unknown-license:npm:a@1.0.0"]
	if !ok {
		t.Fatalf("record not keyed by finding ID: %v", recs)
	}
	if rec.Status != "affected" || rec.Source != license.CDXSourceName {
		t.Errorf("unexpected record: %+v", rec)
	}
	if len(rec.Locations) != 1 || rec.Locations[0].File != "package.json" {
		t.Errorf("source file should be mirrored into Locations, got %+v", rec.Locations)
	}
}

// ── cbom / aibom key builders ────────────────────────────────────────────────

func TestCBOMFindingRecords(t *testing.T) {
	det := cyclonedx.CryptoDetections{
		Assets: []cyclonedx.CryptoAsset{
			{SPDXID: "SHA-1", Primitive: "hash", PQCStatus: "deprecated",
				Evidence: []cyclonedx.CryptoEvidence{{Locator: "hash.go", Snippet: "sha1.New()"}}},
			{SPDXID: "AES-256", Primitive: "block-cipher", PQCStatus: "quantum-safe"},
		},
		Libraries:    []cyclonedx.CryptoLib{{ID: "openssl", Name: "OpenSSL", Provider: "openssl"}},
		Certificates: []cyclonedx.CryptoCert{{Name: "server.pem", Subject: "CN=a", Issuer: "CN=b", NotAfter: "2030-01-01T00:00:00Z"}},
	}
	recs := cbomFindingRecords(det)

	sha1, ok := recs["CBOM:asset:SHA-1:hash"]
	if !ok {
		t.Fatalf("SHA-1 asset key missing: %v", keysOf(recs))
	}
	if sha1.Status != "affected" || sha1.Severity != "medium" {
		t.Errorf("deprecated algorithm should be an affected/medium finding, got %+v", sha1)
	}
	if len(sha1.Locations) != 1 || sha1.Locations[0].File != "hash.go" {
		t.Errorf("evidence locator should become a Location, got %+v", sha1.Locations)
	}

	aes := recs["CBOM:asset:AES-256:block-cipher"]
	if aes.Status != memory.StatusInventory {
		t.Errorf("quantum-safe algorithm should be inventory, got %q", aes.Status)
	}
	if _, ok := recs["CBOM:lib:openssl:openssl"]; !ok {
		t.Errorf("library key missing: %v", keysOf(recs))
	}
	if _, ok := recs["CBOM:cert:CN=a:CN=b:2030-01-01T00:00:00Z"]; !ok {
		t.Errorf("certificate key missing: %v", keysOf(recs))
	}
	if len(sha1.Aliases) != 0 {
		t.Errorf("assets carry no alias — the synthetic key names the VEX statement, got %v", sha1.Aliases)
	}
}

func TestCBOMReconcileScope(t *testing.T) {
	all := cbomReconcileScope(cbomPasses{Source: true, Config: true, Certs: true, Deps: true})
	if len(all) != 3 {
		t.Errorf("all passes should reconcile all three prefixes, got %v", all)
	}
	// --no-certs must not resolve certificates.
	noCerts := cbomReconcileScope(cbomPasses{Source: true, Config: true, Deps: true})
	for _, p := range noCerts {
		if p == "CBOM:cert:" {
			t.Error("--no-certs must not put certificates in reconciliation scope")
		}
	}
	// Nothing eligible must reconcile nothing — not everything.
	none := cbomReconcileScope(cbomPasses{})
	if len(none) == 0 {
		t.Fatal("an empty prefix list would reconcile every record")
	}
}

func TestAIBOMFindingRecords(t *testing.T) {
	det := cyclonedx.AIDetections{
		Tools:     []cyclonedx.AITool{{ID: "claude-code", Name: "Claude Code"}},
		Libraries: []cyclonedx.AILibrary{{ID: "openai-python", Name: "openai"}},
		Models:    []cyclonedx.AIModel{{Name: "gpt-4o", ViaSDK: "openai-python"}},
	}
	recs := aibomFindingRecords(det)
	for _, want := range []string{
		"AIBOM:tool:claude-code",
		"AIBOM:library:openai-python",
		"AIBOM:model:gpt-4o:openai-python",
	} {
		rec, ok := recs[want]
		if !ok {
			t.Errorf("missing key %q; have %v", want, keysOf(recs))
			continue
		}
		if rec.Status != memory.StatusInventory {
			t.Errorf("%s: an AI bill of materials is inventory, got status %q", want, rec.Status)
		}
		if len(rec.Aliases) != 0 {
			t.Errorf("%s: components carry no alias — the synthetic key names the VEX statement", want)
		}
		if rec.Package == "" {
			t.Errorf("%s: the human-readable name should ride in Package", want)
		}
	}
}

func TestAIBOMReconcileScope(t *testing.T) {
	all := aibomReconcileScope(aibomPasses{Env: true, Source: true, Commits: true, Iac: true})
	if len(all) != 5 {
		t.Errorf("all passes should reconcile all five prefixes, got %v", all)
	}
	// --no-source must not resolve libraries or models.
	noSource := aibomReconcileScope(aibomPasses{Env: true, Commits: true, Iac: true})
	for _, p := range noSource {
		if p == "AIBOM:library:" || p == "AIBOM:model:" {
			t.Errorf("--no-source must not put %q in reconciliation scope", p)
		}
	}
	// --no-iac must not resolve models (IaC also produces them) nor infra/data.
	noIac := aibomReconcileScope(aibomPasses{Env: true, Source: true, Commits: true})
	for _, p := range noIac {
		if p == "AIBOM:model:" || p == "AIBOM:infra:" || p == "AIBOM:data:" {
			t.Errorf("--no-iac must not put %q in reconciliation scope", p)
		}
	}
	// --no-env must not resolve tools: a tool detected only via env vars is
	// still installed when the variable is unset.
	noEnv := aibomReconcileScope(aibomPasses{Source: true, Commits: true})
	for _, p := range noEnv {
		if p == "AIBOM:tool:" {
			t.Error("--no-env must not put tools in reconciliation scope")
		}
	}
	if len(aibomReconcileScope(aibomPasses{})) == 0 {
		t.Fatal("an empty prefix list would reconcile every record")
	}
}

// --disable-memory must leave the filesystem alone entirely.
func TestDisableMemory_NoArtefacts(t *testing.T) {
	prev := disableMemory
	disableMemory = true
	t.Cleanup(func() { disableMemory = prev })

	root := t.TempDir()
	reconcileCBOMMemory(root, nil, cyclonedx.CryptoDetections{
		Assets: []cyclonedx.CryptoAsset{{SPDXID: "MD5", Primitive: "hash", PQCStatus: "deprecated"}},
	}, cbomPasses{Source: true, Config: true, Certs: true, Deps: true})
	reconcileAIBOMMemory(root, nil, cyclonedx.AIDetections{
		Tools: []cyclonedx.AITool{{ID: "claude-code", Name: "Claude Code"}},
	}, aibomPasses{Env: true, Source: true, Commits: true})
	reconcileMalscanMemory(root, nil, &malscanResult{
		Findings: []malscanFinding{{Fingerprint: "fp-1", RuleID: "R1", Severity: "critical"}},
	})

	if entries, err := os.ReadDir(filepath.Join(root, ".vulnetix")); err == nil && len(entries) > 0 {
		t.Errorf("--disable-memory wrote %d file(s) into .vulnetix", len(entries))
	}
}

func TestMalscanFindingRecords(t *testing.T) {
	res := &malscanResult{Findings: []malscanFinding{
		{Fingerprint: "fp-1", RuleID: "IOC-STIX-MATCH", Severity: "critical",
			Ecosystem: "npm", File: "node_modules/evil/index.js", StartLine: 4, Snippet: "eval("},
		{Fingerprint: "fp-2", RuleID: "BADHASH", Severity: "high"}, // package-level, no file
	}}
	recs := malscanFindingRecords(res)
	if len(recs) != 2 {
		t.Fatalf("expected 2 records, got %d", len(recs))
	}
	if recs["fp-1"].Aliases[0] != "IOC-STIX-MATCH" {
		t.Errorf("rule ID should ride in Aliases so VEX names the rule, got %+v", recs["fp-1"].Aliases)
	}
	if len(recs["fp-1"].Locations) != 1 {
		t.Errorf("file-anchored finding should carry a Location, got %+v", recs["fp-1"].Locations)
	}
	if len(recs["fp-2"].Locations) != 0 {
		t.Errorf("package-level finding has no location, got %+v", recs["fp-2"].Locations)
	}
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
