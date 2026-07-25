package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vulnetix/vdb-sca-match/sarif"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// newTestSubmitter builds a submitter that publishes nothing, which is enough to
// exercise the whole classify → validate → decompose → report path.
func newTestSubmitter(ci *vdb.CliCIContext) *ghaSubmitter {
	return &ghaSubmitter{
		env:    vdb.CliEnv{CliVersion: "v3.65.0", CI: ci},
		dryRun: true,
		logf:   func(string, ...any) {},
		warnf:  func(string, ...any) {},
	}
}

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// The two shapes `tool > out.sarif || true` leaves behind. Both used to reach
// the API and come back as an opaque 503; both must now fail locally with a
// reason that names the cause.
func TestPublishRejectsBrokenRedirectOutput(t *testing.T) {
	s := newTestSubmitter(nil)

	t.Run("zero-byte", func(t *testing.T) {
		res := s.publishFile("zizmor", writeTemp(t, "zizmor.sarif", ""))
		if res.Status != "error" {
			t.Fatalf("status = %q, want error", res.Status)
		}
		if !strings.Contains(res.Error, "empty") {
			t.Errorf("error should name the emptiness: %q", res.Error)
		}
		if !strings.Contains(res.Error, "--output") {
			t.Errorf("error should point at the fix: %q", res.Error)
		}
	})

	t.Run("truncated", func(t *testing.T) {
		res := s.publishFile("terrascan", writeTemp(t, "terrascan.sarif", `{"version":"2.1.0","runs":[{"tool"`))
		if res.Status != "error" {
			t.Fatalf("status = %q, want error", res.Status)
		}
	})
}

// vulnetix.yml uploads .vulnetix/*.sarif and *.cdx.json as workflow artifacts,
// and this command collects every artifact in the run. Those reports were
// already persisted by the subcommand that produced them, so republishing them
// would mint a second ScannerRun for every first-party scan and double every
// finding count — silently, across every repo running the workflow.
func TestPublishSkipsVulnetixOwnReports(t *testing.T) {
	s := newTestSubmitter(nil)

	t.Run("own SARIF", func(t *testing.T) {
		// The driver name sast.BuildSARIF writes.
		doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"vulnetix","version":"v3.73.0",
		  "rules":[{"id":"VULNETIX-SQL-001","properties":{"severity":"high"}}]}},
		  "results":[{"ruleId":"VULNETIX-SQL-001","level":"error","message":{"text":"x"},
		  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1}}}]}]}]}`
		res := s.publishFile("sast", writeTemp(t, "sast.sarif", doc))

		if res.Status != "skipped" {
			t.Fatalf("status = %q, want skipped (would double-count the scan)", res.Status)
		}
		if !strings.Contains(res.Reason, "already published") {
			t.Errorf("reason should explain the duplicate: %q", res.Reason)
		}
	})

	t.Run("own SBOM", func(t *testing.T) {
		doc := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,
		  "metadata":{"tools":{"components":[{"name":"Vulnetix SCA","version":"v3.73.0","type":"application"}]}},
		  "components":[{"type":"library","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21"}]}`
		res := s.publishFile("sca", writeTemp(t, "sbom.cdx.json", doc))

		if res.Status != "skipped" {
			t.Fatalf("status = %q, want skipped", res.Status)
		}
	})

	// A genuine third-party report must still publish.
	t.Run("third-party still publishes", func(t *testing.T) {
		res := s.publishFile("gosec", writeTemp(t, "gosec.sarif", gosecSARIFDoc))
		if res.Status != "uploaded" {
			t.Fatalf("status = %q, want uploaded (%s)", res.Status, res.Reason)
		}
	})
}

func TestIsVulnetixOwnTool(t *testing.T) {
	for _, name := range []string{"vulnetix", "Vulnetix SCA", "Vulnetix Malscan", "vulnetix-containers", "VULNETIX SAST"} {
		if !isVulnetixOwnTool(name) {
			t.Errorf("%q should be recognised as our own tool", name)
		}
	}
	// Names that merely start with the same letters are not ours.
	for _, name := range []string{"gosec", "grype", "Trivy", "vulnerability-scanner", "", "vulnetixual"} {
		if isVulnetixOwnTool(name) {
			t.Errorf("%q should not be treated as our own tool", name)
		}
	}
}

// A log or junit file inside an artifact is not a failure — a publish job must
// not break because a scanner also uploaded its stdout.
func TestPublishSkipsNonReportFiles(t *testing.T) {
	s := newTestSubmitter(nil)
	res := s.publishFile("gosec", writeTemp(t, "run.log", "scanning...\ndone\n"))

	if res.Status != "skipped" {
		t.Fatalf("status = %q, want skipped", res.Status)
	}
	if res.Reason == "" {
		t.Error("a skip must state its reason")
	}
}

const gosecSARIFDoc = `{
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {
      "name": "gosec", "version": "2.28.0", "organization": "securego",
      "rules": [{"id": "G404", "name": "weak-random",
        "properties": {"security-severity": "8.1", "tags": ["CWE-338"]}}]
    }},
    "results": [{
      "ruleId": "G404", "ruleIndex": 0, "level": "warning",
      "message": {"text": "Use of weak random number generator"},
      "locations": [{"physicalLocation": {
        "artifactLocation": {"uri": "internal/token/token.go"},
        "region": {"startLine": 42}
      }}]
    }]
  }]
}`

func TestPublishSARIFClassifiesAndAttributes(t *testing.T) {
	s := newTestSubmitter(&vdb.CliCIContext{RunID: 30155614396, RunAttempt: 1})
	res := s.publishFile("gosec", writeTemp(t, "gosec.sarif", gosecSARIFDoc))

	if res.Status != "uploaded" {
		t.Fatalf("status = %q (%s)", res.Status, res.Error)
	}
	if res.Category != string(sarif.CategorySAST) {
		t.Errorf("category = %q, want SAST", res.Category)
	}
	if res.Tool != "gosec" || res.ToolVersion != "2.28.0" {
		t.Errorf("attribution = %s/%s, want gosec/2.28.0", res.Tool, res.ToolVersion)
	}
	if res.Findings != 1 {
		t.Errorf("findings = %d, want 1", res.Findings)
	}
}

// The analysis key is what makes a re-published workflow run idempotent instead
// of doubling every count.
func TestAnalysisKeyIdentifiesRunAttemptAndTool(t *testing.T) {
	s := newTestSubmitter(&vdb.CliCIContext{RunID: 30155614396, RunAttempt: 2})
	if got, want := s.analysisKey("gosec"), "gha:30155614396:2:gosec"; got != want {
		t.Errorf("analysisKey = %q, want %q", got, want)
	}

	// A missing attempt is attempt 1, not attempt 0 — otherwise the first run of
	// every workflow would key differently from its own re-run.
	s = newTestSubmitter(&vdb.CliCIContext{RunID: 7})
	if got, want := s.analysisKey("grype"), "gha:7:1:grype"; got != want {
		t.Errorf("analysisKey = %q, want %q", got, want)
	}

	// Outside CI there is no run to key on, so there is no key.
	s = newTestSubmitter(nil)
	if got := s.analysisKey("grype"); got != "" {
		t.Errorf("analysisKey = %q, want empty outside CI", got)
	}
}

const syftSBOM = `{
  "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
  "metadata": {"tools": {"components": [{"name": "syft", "version": "1.42.3", "type": "application", "author": "anchore"}]}},
  "components": [
    {"type": "library", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21",
     "hashes": [{"alg": "SHA-256", "content": "e6c4f1f3e0d0c2a1b5d8f7a9c3e2b4d6a8f0c2e4b6d8a0f2c4e6b8d0a2f4c6e8"}]},
    {"type": "library", "name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"},
    {"type": "library", "name": "duplicate", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
    {"type": "file", "name": "README.md"}
  ]
}`

func TestPublishCycloneDXExtractsPackages(t *testing.T) {
	s := newTestSubmitter(nil)
	res := s.publishFile("syft", writeTemp(t, "sbom.cdx.json", syftSBOM))

	if res.Status != "uploaded" {
		t.Fatalf("status = %q (%s)", res.Status, res.Error)
	}
	if res.Tool != "syft" || res.ToolVersion != "1.42.3" {
		t.Errorf("attribution = %s/%s, want syft/1.42.3", res.Tool, res.ToolVersion)
	}
	// Two distinct purls: the duplicate collapses and the purl-less file is
	// dropped.
	if res.Findings != 2 {
		t.Errorf("packages = %d, want 2 (duplicate collapsed, file component dropped)", res.Findings)
	}
	if res.Category != string(sarif.CategorySCA) {
		t.Errorf("category = %q, want SCA", res.Category)
	}
}

const spdxSBOM = `{
  "spdxVersion": "SPDX-2.3", "name": "test",
  "creationInfo": {"creators": ["Tool: syft-1.42.3", "Organization: Anchore"]},
  "packages": [
    {"name": "lodash", "versionInfo": "4.17.21",
     "externalRefs": [{"referenceCategory": "PACKAGE_MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.21"}]},
    {"name": "no-purl", "versionInfo": "1.0.0"}
  ]
}`

func TestPublishSPDXExtractsPackages(t *testing.T) {
	s := newTestSubmitter(nil)
	res := s.publishFile("syft-spdx", writeTemp(t, "sbom.spdx.json", spdxSBOM))

	if res.Status != "uploaded" {
		t.Fatalf("status = %q (%s)", res.Status, res.Error)
	}
	if res.Tool != "syft-1.42.3" {
		t.Errorf("tool = %q; the creator entry names it", res.Tool)
	}
	if res.Findings != 1 {
		t.Errorf("packages = %d, want 1 (the purl-less package is unmatched and dropped)", res.Findings)
	}
	// SPDX writes the category with an underscore where the spec's older form
	// used a hyphen; both must be accepted or every SPDX SBOM yields nothing.
	if res.Category != string(sarif.CategorySCA) {
		t.Errorf("category = %q, want SCA", res.Category)
	}
}

// Rule descriptors must ride the first chunk: the server's append path bumps the
// result count but never recounts rules, so a later chunk carrying them would
// leave the run reporting zero rules.
func TestChunkingKeepsRulesOnFirstChunkOnly(t *testing.T) {
	log := &sarif.Log{Version: "2.1.0", Runs: []sarif.Run{{
		Tool: sarif.Tool{Driver: sarif.ToolComponent{
			Name:  "gosec",
			Rules: []sarif.ReportingDescriptor{{ID: "G404"}},
		}},
	}}}

	// Enough findings to force more than one chunk.
	findings := make([]sarif.Finding, sarifChunkMaxFindings+10)
	for i := range findings {
		findings[i] = sarif.Finding{RuleID: "G404", Severity: "high", File: "a.go", StartLine: i + 1}
	}

	chunks := chunkGHAFindings(log, findings)
	if len(chunks) < 2 {
		t.Fatalf("chunks = %d, want at least 2", len(chunks))
	}

	firstRuns, _ := chunks[0].doc["runs"].([]any)
	if len(firstRuns) == 0 {
		t.Error("chunk 0 must carry the full document, including rule descriptors")
	}
	for i, ch := range chunks[1:] {
		runs, _ := ch.doc["runs"].([]any)
		if len(runs) != 0 {
			t.Errorf("chunk %d should carry a stub document, got %d runs", i+1, len(runs))
		}
	}

	total := 0
	for _, ch := range chunks {
		total += len(ch.findings)
	}
	if total != len(findings) {
		t.Errorf("chunking lost findings: %d of %d", total, len(findings))
	}
}

// An empty document still produces one chunk, so an enabled-but-clean scanner
// records coverage rather than vanishing.
func TestChunkingEmptyDocumentStillSubmits(t *testing.T) {
	log := &sarif.Log{Version: "2.1.0", Runs: []sarif.Run{{
		Tool: sarif.Tool{Driver: sarif.ToolComponent{Name: "terrascan"}},
	}}}
	chunks := chunkGHAFindings(log, nil)
	if len(chunks) != 1 {
		t.Fatalf("chunks = %d, want 1", len(chunks))
	}
	if len(chunks[0].findings) != 0 {
		t.Errorf("empty submission should carry no findings, got %d", len(chunks[0].findings))
	}
}

// The workspace is what SARIF file paths are relativised against; the server
// needs the same value to reproduce this decomposition.
func TestWorkspacePrefersCIOverGit(t *testing.T) {
	s := &ghaSubmitter{env: vdb.CliEnv{
		Git: &vdb.CliGitContext{RepoRoot: "/local/checkout"},
		CI:  &vdb.CliCIContext{Workspace: "/runner/work/repo"},
	}}
	if got := s.workspace(); got != "/runner/work/repo" {
		t.Errorf("workspace = %q, want the CI workspace", got)
	}

	s = &ghaSubmitter{env: vdb.CliEnv{Git: &vdb.CliGitContext{RepoRoot: "/local/checkout"}}}
	if got := s.workspace(); got != "/local/checkout" {
		t.Errorf("workspace = %q, want the git root as fallback", got)
	}
}
