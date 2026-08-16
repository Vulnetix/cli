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

// Each chunk must carry exactly the results it claims. The server re-decomposes
// whatever document it receives, so a chunk carrying the whole document would
// make the server persist every finding — and then persist them again as the
// later chunks appended their share.
func TestChunkingPartitionsResultsWithoutOverlap(t *testing.T) {
	total := sarifChunkMaxFindings + 10
	run := sarif.Run{
		Tool: sarif.Tool{Driver: sarif.ToolComponent{
			Name:  "gosec",
			Rules: []sarif.ReportingDescriptor{{ID: "G404"}},
		}},
	}
	for i := range total {
		run.Results = append(run.Results, sarif.Result{
			RuleID:  "G404",
			Message: sarif.Message{Text: "finding"},
			Locations: []sarif.Location{{PhysicalLocation: &sarif.PhysicalLocation{
				ArtifactLocation: &sarif.ArtifactLocation{URI: "a.go"},
				Region:           &sarif.Region{StartLine: i + 1},
			}}},
		})
	}
	log := &sarif.Log{Version: "2.1.0", Runs: []sarif.Run{run}}

	chunks := chunkGHASARIF(log)
	if len(chunks) < 2 {
		t.Fatalf("chunks = %d, want at least 2", len(chunks))
	}

	// Every result appears exactly once across the chunks.
	seen := map[int]int{}
	sum := 0
	for _, ch := range chunks {
		sum += ch.results
		runs, _ := ch.doc["runs"].([]any)
		for _, r := range runs {
			results, _ := r.(map[string]any)["results"].([]any)
			for _, res := range results {
				locs := res.(map[string]any)["locations"].([]any)
				region := locs[0].(map[string]any)["physicalLocation"].(map[string]any)["region"].(map[string]any)
				line := int(region["startLine"].(float64))
				seen[line]++
			}
		}
	}
	if sum != total {
		t.Errorf("chunk result counts sum to %d, want %d", sum, total)
	}
	if len(seen) != total {
		t.Errorf("distinct results across chunks = %d, want %d", len(seen), total)
	}
	for line, n := range seen {
		if n != 1 {
			t.Errorf("result at line %d appears %d times; chunks must not overlap", line, n)
		}
	}
}

// Rule descriptors must ride the first chunk: the server's append path bumps the
// result count but never recounts rules, so a later chunk carrying them would
// leave the run reporting zero rules.
func TestChunkingKeepsRulesOnFirstChunkOnly(t *testing.T) {
	run := sarif.Run{
		Tool: sarif.Tool{Driver: sarif.ToolComponent{
			Name:  "gosec",
			Rules: []sarif.ReportingDescriptor{{ID: "G404"}},
		}},
	}
	for i := range sarifChunkMaxFindings + 10 {
		run.Results = append(run.Results, sarif.Result{RuleID: "G404", Message: sarif.Message{Text: "x"},
			Locations: []sarif.Location{{PhysicalLocation: &sarif.PhysicalLocation{
				ArtifactLocation: &sarif.ArtifactLocation{URI: "a.go"},
				Region:           &sarif.Region{StartLine: i + 1}}}}})
	}
	chunks := chunkGHASARIF(&sarif.Log{Version: "2.1.0", Runs: []sarif.Run{run}})
	if len(chunks) < 2 {
		t.Fatalf("chunks = %d, want at least 2", len(chunks))
	}

	rulesIn := func(ch ghaChunk) int {
		runs, _ := ch.doc["runs"].([]any)
		n := 0
		for _, r := range runs {
			tool, _ := r.(map[string]any)["tool"].(map[string]any)
			driver, _ := tool["driver"].(map[string]any)
			rules, _ := driver["rules"].([]any)
			n += len(rules)
		}
		return n
	}
	if rulesIn(chunks[0]) == 0 {
		t.Error("chunk 0 must carry the rule descriptors")
	}
	for i, ch := range chunks[1:] {
		if got := rulesIn(ch); got != 0 {
			t.Errorf("chunk %d carries %d rules; only chunk 0 should", i+1, got)
		}
		// but it must still name its tool, or the server rejects it
		runs, _ := ch.doc["runs"].([]any)
		tool, _ := runs[0].(map[string]any)["tool"].(map[string]any)
		driver, _ := tool["driver"].(map[string]any)
		if driver["name"] != "gosec" {
			t.Errorf("chunk %d lost its tool name; the server would reject it", i+1)
		}
	}
}

// An empty document still produces one chunk, so an enabled-but-clean scanner
// records coverage rather than vanishing.
func TestChunkingEmptyDocumentStillSubmits(t *testing.T) {
	log := &sarif.Log{Version: "2.1.0", Runs: []sarif.Run{{
		Tool: sarif.Tool{Driver: sarif.ToolComponent{Name: "terrascan"}},
	}}}
	chunks := chunkGHASARIF(log)
	if len(chunks) != 1 {
		t.Fatalf("chunks = %d, want 1", len(chunks))
	}
	if chunks[0].results != 0 {
		t.Errorf("empty submission should carry no results, got %d", chunks[0].results)
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

// A 200 that stored nothing is not a publish. The server returns exactly that
// under the shared community credential, which the CLI falls back to whenever a
// real one cannot be read — an unset VULNETIX_API_KEY, or a keyring it cannot
// unlock in a headless session. Before this, such a run printed "published",
// a category and a finding count, and left no ScannerRun anywhere.
func TestNotRecordedIsCountedSeparatelyFromSuccess(t *testing.T) {
	results := []ghaFileResult{
		{Name: "gosec", File: "gosec.sarif", Status: "uploaded", Persisted: true, SnapshotUuid: "abc"},
		{Name: "semgrep", File: "semgrep.sarif", Status: "uploaded", Persisted: false, Reason: notPersistedReason},
		{Name: "readme", File: "README.md", Status: "skipped"},
		{Name: "broken", File: "broken.sarif", Status: "error", Error: "invalid"},
	}

	if got := countNotRecorded(results); got != 1 {
		t.Errorf("countNotRecorded = %d, want 1", got)
	}

	// The not-recorded file still counts as a success for the exit code: the
	// request did succeed, and failing the build on a community credential
	// would break every unauthenticated user's pipeline.
	uploaded, failed, skipped := tallyGHAResults(results)
	if uploaded != 2 || failed != 1 || skipped != 1 {
		t.Errorf("tally = (%d, %d, %d), want (2, 1, 1)", uploaded, failed, skipped)
	}

	// A dry run reports uploaded with no snapshot, and must not be mistaken for
	// the community-credential case.
	if got := countNotRecorded([]ghaFileResult{
		{Status: "uploaded", Persisted: false, Reason: "dry run; nothing was sent"},
	}); got != 0 {
		t.Errorf("a dry run must not count as not-recorded, got %d", got)
	}
}
