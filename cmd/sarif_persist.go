package cmd

// Phase-2 SARIF persistence hook for SAST / Secrets / IaC / Containers / License.
//
// `postScanSARIF` is called once per CLI scan and:
//   1) partitions the local SAST-engine findings by rule.Kind
//   2) builds one SARIF document per non-empty kind via internal/sast.BuildSARIF
//   3) reduces local Findings → []vdb.CliSARIFFinding (with memory.yaml VEX)
//   4) POSTs each one to its matching /v2/cli.<kind> endpoint
//   5) prints `Snapshot: <url>` for every successful submission
//
// Failures are non-fatal: the local SARIF file is still authoritative.

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/internal/license"
	"github.com/vulnetix/cli/v3/internal/memory"
	"github.com/vulnetix/cli/v3/internal/sast"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// sarifScanKind groups the dispatch metadata for one SAST-engine rule kind.
type sarifScanKind struct {
	kind     string // matches sast.RuleMetadata.Kind ("sast" | "secrets" | "iac" | "oci")
	category string // server-side Category value
	label    string // human-readable name used in CLI output
}

// snapshotLink is one successful SARIF submission's ingestion snapshot, surfaced
// as an artifact link in the scan summary.
type snapshotLink struct {
	Label string
	URL   string
}

var sarifKinds = []sarifScanKind{
	{kind: "sast", category: "sast", label: "SAST"},
	{kind: "secrets", category: "secrets", label: "Secrets"},
	{kind: "iac", category: "iac", label: "IaC"},
	{kind: "oci", category: "containers", label: "Containers"},
}

// postScanSARIF is the single entry point. Called from scan.go after the local
// SARIF is on disk. Splits findings by rule kind and posts each non-empty kind
// to its matching /v2/cli.<kind> endpoint. When baseSnapshotUuid is set, the
// first SARIF request attaches to that existing SCA snapshot; otherwise the
// SARIF endpoint creates its own snapshot as before.
func postScanSARIF(report *sast.SASTReport, enabledKinds map[string]bool, gitCtx *gitctx.GitContext, rootPath string, snippetContext int, baseSnapshotUuid string, suppressions []vdb.CliSuppressionMint, testConfigs []vdb.CliTestConfigMetadata, w io.Writer) ([]snapshotLink, map[string]string, []vdb.CliSuppressionResult) {
	if report == nil {
		return nil, nil, nil
	}
	if w == nil {
		w = os.Stderr
	}
	client := newCliClient()
	if client == nil {
		return nil, nil, nil
	}
	// Use the scan target's git context (not the CWD's) so the snapshot's repo
	// identity matches --path.
	env := envForCliWithGit(gitCtx)
	memRecords := loadMemoryRecordsForSARIF(gitCtx)

	var snapshots []snapshotLink
	var suppResults []vdb.CliSuppressionResult
	uuidByCategory := make(map[string]string)
	byKind := partitionFindingsByKind(report.Findings, report.Rules)
	// The reconciled suppression set is repo-scoped, not kind-scoped, so it ships
	// once on the first submitted kind to avoid duplicate upserts.
	pendingSupp := suppressions
	sentSupp := false
	for _, sk := range sarifSubmitKinds(enabledKinds) {
		// An enabled scanner that ran clean still submits — the empty bucket
		// builds a valid empty SARIF doc, and the server records a ScannerRun +
		// IngestionSnapshot on any SARIF body (v2_cli_scan_handlers.go), so the
		// GUI reflects "assessed, 0 findings" instead of no coverage at all.
		bucket := byKind[sk.kind]
		bucket.degradations = report.Degradations
		var thisSupp []vdb.CliSuppressionMint
		if !sentSupp {
			thisSupp = pendingSupp
			sentSupp = true // attempted on this kind; never resend (avoid dup upsert)
		}
		// Detected test-runner config files describe the SAST test surface, so
		// they ride the SAST submission's env only (each kind gets its own
		// snapshot; attaching everywhere would duplicate the rows).
		kindEnv := env
		if sk.kind == "sast" {
			kindEnv.TestConfigs = testConfigs
		}
		link, snapshotUuid, results, ok := submitSARIFKind(client, kindEnv, sk, bucket, memRecords, rootPath, snippetContext, baseSnapshotUuid, thisSupp, w)
		if len(thisSupp) > 0 && len(results) > 0 {
			suppResults = results
		}
		if ok {
			snapshots = append(snapshots, link)
			if snapshotUuid != "" {
				uuidByCategory[sk.category] = snapshotUuid
			}
		}
	}
	return snapshots, uuidByCategory, suppResults
}

// sarifSubmitKinds returns the SARIF-family kinds to submit for this scan: every
// ENABLED kind, whether or not it produced findings. An enabled-but-clean
// scanner still submits (empty SARIF) so the backend records coverage; a
// disabled scanner (its --no-<kind> flag set, so `enabled[kind]` is false)
// submits nothing. Order follows sarifKinds for stable snapshot links.
func sarifSubmitKinds(enabled map[string]bool) []sarifScanKind {
	out := make([]sarifScanKind, 0, len(sarifKinds))
	for _, sk := range sarifKinds {
		if enabled[sk.kind] {
			out = append(out, sk)
		}
	}
	return out
}

// sarifChunkByteBudget bounds the per-request typed-findings JSON size. The
// wire body carries the findings array AND a per-chunk SARIF doc that embeds the
// same code snippets, so the actual body is roughly double this — the budget is
// set well under the server's 8 MiB limit (v2_cli_common.go) to leave margin
// for the duplicated SARIF + rule descriptors.
const sarifChunkByteBudget = 3 << 20 // 3 MiB

// sarifChunkMaxFindings is a secondary guard so a kind with many tiny findings
// still splits into reasonable requests (also stays under the 50000 server cap).
const sarifChunkMaxFindings = 2000

// submitSARIFKind builds the SARIF doc(s) for one kind and POSTs them, splitting
// large submissions into sub-8-MiB chunks. Chunk 0 creates the snapshot/run;
// chunks 1..N carry its uuid so the server appends under one snapshot. Returns
// the (single) ingestion snapshot link, the snapshot UUID, and an ok flag.
func submitSARIFKind(client *vdb.Client, env vdb.CliEnv, sk sarifScanKind, bucket kindBucket, memRecords map[string]memory.FindingRecord, rootPath string, snippetContext int, baseSnapshotUuid string, suppressions []vdb.CliSuppressionMint, w io.Writer) (snapshotLink, string, []vdb.CliSuppressionResult, bool) {
	// Make the per-kind tool intent explicit (server is authoritative, but this
	// keeps the env block self-describing): "Vulnetix SAST", "Vulnetix IaC", etc.
	env.ToolMetadata = &vdb.CliSBOMToolMetadata{
		ToolName:    "Vulnetix " + sk.label,
		ToolVersion: version,
		ToolVendor:  "Vulnetix",
		ToolHash:    commit,
	}

	// Build typed findings once (with snippet capture + memory.yaml VEX), keeping
	// them index-aligned with bucket.findings so each chunk's SARIF doc is built
	// from the matching sast.Finding subset.
	apiFindings := make([]vdb.CliSARIFFinding, len(bucket.findings))
	for i, f := range bucket.findings {
		apiFindings[i] = buildAPISARIFFinding(f, memRecords, rootPath, snippetContext)
	}

	chunks := chunkSARIFFindings(bucket.findings, apiFindings)

	var link snapshotLink
	var suppResults []vdb.CliSuppressionResult
	snapshotUuid := baseSnapshotUuid
	anyOK := false
	for i, ch := range chunks {
		sarifLog := sast.BuildSARIF(ch.sast, bucket.rules, version)
		sarifLog.AddExecutionNotifications(bucket.degradations)
		req := vdb.CliSARIFRequest{
			SARIF:    sarifLogToMap(sarifLog),
			Findings: ch.api,
		}
		// Reconciled suppressions ride the first chunk only (repo-scoped upsert).
		if i == 0 {
			req.Suppressions = suppressions
		}
		if snapshotUuid != "" {
			req.IngestionSnapshotUuid = snapshotUuid
		}
		if i > 0 {
			if snapshotUuid == "" {
				// Chunk 0 never persisted a snapshot (unauth / server skip); the
				// remaining chunks can't anchor to one, so stop — local SARIF on
				// disk is still authoritative.
				break
			}
		}
		resp, err := dispatchSARIFRequest(client, env, sk.category, req)
		if err != nil {
			if verbose {
				fmt.Fprintf(w, "  /v2/cli.%s chunk %d/%d submit failed: %v\n", sk.category, i+1, len(chunks), err)
			}
			if i == 0 {
				return snapshotLink{}, "", nil, false
			}
			continue
		}
		anyOK = true
		if i == 0 && resp != nil {
			suppResults = resp.Data.Suppressions
			if resp.Data.IngestionSnapshot != nil {
				snapshotUuid = resp.Data.IngestionSnapshot.Uuid
				link = snapshotLink{Label: sk.label, URL: resp.Data.IngestionSnapshot.URL}
			}
		}
	}
	if !anyOK || link.URL == "" {
		return snapshotLink{}, "", suppResults, false
	}
	return link, snapshotUuid, suppResults, true
}

// buildAPISARIFFinding converts one local SAST finding into the typed API shape,
// capturing its code snippet and merging any memory.yaml VEX hint.
func buildAPISARIFFinding(f sast.Finding, memRecords map[string]memory.FindingRecord, rootPath string, snippetContext int) vdb.CliSARIFFinding {
	ruleName := ""
	description := ""
	cwes := []int{}
	tags := []string{}
	if f.Metadata != nil {
		ruleName = f.Metadata.Name
		description = f.Metadata.Description
		cwes = append(cwes, f.Metadata.CWE...)
		tags = append(tags, f.Metadata.Tags...)
	}
	mem := memHitForRule(memRecords, f.RuleID)
	snippet, snipStart, snipEnd := captureSnippet(rootPath, f.ArtifactURI, f.StartLine, f.EndLine, snippetContext)
	if snippet == "" && f.Snippet != "" {
		snippet = f.Snippet
		snipStart = f.StartLine
		snipEnd = f.EndLine
	}
	return vdb.CliSARIFFinding{
		RuleID:                 f.RuleID,
		RuleName:               ruleName,
		Description:            description,
		Message:                f.Message,
		Severity:               f.Severity,
		Level:                  f.Level,
		File:                   f.ArtifactURI,
		StartLine:              f.StartLine,
		EndLine:                f.EndLine,
		Fingerprint:            f.Fingerprint,
		CWEs:                   cwes,
		Tags:                   tags,
		SARIFGuid:              f.Fingerprint,
		CodeSnippet:            snippet,
		SnippetStartLine:       snipStart,
		SnippetEndLine:         snipEnd,
		MemoryVexStatus:        mem.Status,
		MemoryVexJustification: mem.Justification,
		MemoryVexAction:        mem.ActionResponse,
		IsTestSuite:            f.IsTestSuite,
		TestFramework:          f.TestFramework,
		TestLanguage:           f.TestLanguage,
		TestConfidence:         f.TestConfidence,
		TestMatchedPattern:     f.TestMatchedPattern,
		TestEvidence:           f.TestEvidence,
	}
}

// sarifChunk pairs a slice of local findings with their index-aligned typed
// findings so each chunk can build a matching per-chunk SARIF doc.
type sarifChunk struct {
	sast []sast.Finding
	api  []vdb.CliSARIFFinding
}

// chunkSARIFFindings greedily groups findings so each chunk's typed-findings
// JSON stays under sarifChunkByteBudget (and sarifChunkMaxFindings). A single
// oversized finding still ships alone. Returns at least one chunk (possibly
// empty, for a probe-style submission).
func chunkSARIFFindings(sastFindings []sast.Finding, apiFindings []vdb.CliSARIFFinding) []sarifChunk {
	if len(apiFindings) == 0 {
		return []sarifChunk{{}}
	}
	var chunks []sarifChunk
	var curSast []sast.Finding
	var curAPI []vdb.CliSARIFFinding
	curBytes := 0
	flush := func() {
		if len(curAPI) == 0 {
			return
		}
		chunks = append(chunks, sarifChunk{sast: curSast, api: curAPI})
		curSast, curAPI, curBytes = nil, nil, 0
	}
	for i := range apiFindings {
		sz := 256 // base per-finding overhead
		if b, err := json.Marshal(apiFindings[i]); err == nil {
			sz = len(b)
		}
		if len(curAPI) > 0 && (curBytes+sz > sarifChunkByteBudget || len(curAPI) >= sarifChunkMaxFindings) {
			flush()
		}
		curSast = append(curSast, sastFindings[i])
		curAPI = append(curAPI, apiFindings[i])
		curBytes += sz
	}
	flush()
	return chunks
}

// dispatchSARIFRequest picks the right typed client method by category. Kept
// in one place so adding a new SARIF endpoint is a single switch arm.
func dispatchSARIFRequest(client *vdb.Client, env vdb.CliEnv, category string, req vdb.CliSARIFRequest) (*vdb.CliResponse[vdb.CliSARIFResponse], error) {
	switch strings.ToLower(category) {
	case "sast":
		return client.CliSAST(env, req)
	case "secrets":
		return client.CliSecrets(env, req)
	case "iac":
		return client.CliIAC(env, req)
	case "containers":
		return client.CliContainers(env, req)
	case "license":
		return client.CliLicense(env, req)
	default:
		return nil, fmt.Errorf("unknown SARIF category %q", category)
	}
}

// kindBucket is the per-kind subset of findings + rules used to assemble a
// SARIF doc that ONLY covers that kind. (BuildSARIF reads f.Metadata to embed
// rule descriptors; we pass the matching rules slice so cross-references work.)
type kindBucket struct {
	findings []sast.Finding
	rules    []sast.RuleMetadata
	// degradations are run-wide capability notes ("git history was not
	// scanned: ...") attached to every kind's SARIF as
	// toolExecutionNotifications, so the backend can tell "assessed clean"
	// from "assessed with reduced coverage".
	degradations []string
}

// partitionFindingsByKind splits a mixed SAST-engine report into per-kind
// buckets. Findings whose rule metadata is missing default to kind "sast".
func partitionFindingsByKind(findings []sast.Finding, rules []sast.RuleMetadata) map[string]kindBucket {
	ruleByID := make(map[string]sast.RuleMetadata, len(rules))
	for _, r := range rules {
		ruleByID[r.ID] = r
	}
	out := make(map[string]kindBucket, 4)
	for _, f := range findings {
		kind := "sast"
		if f.Metadata != nil && f.Metadata.Kind != "" {
			kind = f.Metadata.Kind
		}
		b := out[kind]
		b.findings = append(b.findings, f)
		if r, ok := ruleByID[f.RuleID]; ok {
			// Avoid duplicating rules across findings.
			already := false
			for _, existing := range b.rules {
				if existing.ID == r.ID {
					already = true
					break
				}
			}
			if !already {
				b.rules = append(b.rules, r)
			}
		}
		out[kind] = b
	}
	return out
}

// sarifLogToMap converts a typed *SARIFLog into the map[string]any wire shape
// the server expects. JSON round-trip keeps key order stable and drops omitted
// fields automatically.
func sarifLogToMap(log *sast.SARIFLog) map[string]any {
	if log == nil {
		return map[string]any{
			"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
			"version": "2.1.0",
			"runs":    []any{},
		}
	}
	b, err := json.Marshal(log)
	if err != nil || b == nil {
		return map[string]any{
			"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
			"version": "2.1.0",
			"runs":    []any{},
		}
	}
	var out map[string]any
	if uerr := json.Unmarshal(b, &out); uerr != nil {
		return map[string]any{}
	}
	return out
}

// loadMemoryRecordsForSARIF reads memory.yaml and returns the SAST-findings
// bucket keyed by rule fingerprint, plus the legacy CVE-keyed Findings map.
// Both are consulted in memHitForRule.
func loadMemoryRecordsForSARIF(gitCtx *gitctx.GitContext) map[string]memory.FindingRecord {
	if gitCtx == nil || gitCtx.RepoRootPath == "" {
		return nil
	}
	vulnetixDir := filepath.Join(gitCtx.RepoRootPath, ".vulnetix")
	store, err := memory.Load(vulnetixDir)
	if err != nil || store == nil {
		return nil
	}
	combined := make(map[string]memory.FindingRecord, len(store.Findings))
	for k, v := range store.Findings {
		combined[k] = v
	}
	return combined
}

// memHitForRule returns the memory.yaml VEX hint for a rule id, if any.
// SAST findings are keyed by either rule id or fingerprint.
func memHitForRule(records map[string]memory.FindingRecord, ruleID string) memoryHit {
	if r, ok := records[ruleID]; ok {
		return memoryHit{Status: r.Status, Justification: r.Justification, ActionResponse: r.ActionResponse}
	}
	return memoryHit{}
}

// postLicenseSARIF builds a SARIF document covering every license conflict +
// policy violation in `result` and POSTs it to /v2/cli.license. Mirrors
// postScanSARIF but the input source is the license analyzer rather than the
// SAST engine.
func postLicenseSARIF(result *license.AnalysisResult, rootPath string, snippetContext int) {
	if result == nil {
		return
	}
	client := newCliClient()
	if client == nil {
		return
	}
	findings, rules := license.BuildSARIFFromAnalysis(result)
	// No early-return on an empty finding set: a clean license scan still submits
	// an empty SARIF so the backend records a ScannerRun + snapshot (coverage).

	// Reuse the sast SARIF builder by adapting our license SARIF structs into
	// sast.Finding + sast.RuleMetadata.
	sastFindings := make([]sast.Finding, 0, len(findings))
	sastRules := make([]sast.RuleMetadata, 0, len(rules))
	ruleByID := make(map[string]string, len(rules))
	for _, r := range rules {
		ruleByID[r.ID] = r.Name
		sastRules = append(sastRules, sast.RuleMetadata{
			ID:       r.ID,
			Name:     r.Name,
			Severity: r.Severity,
			Level:    severityToLevel(r.Severity),
			Kind:     "license",
			Tags:     r.Tags,
		})
	}
	for _, f := range findings {
		// Construct a synthetic Metadata pointer so BuildSARIF can attach the
		// rule descriptor for each result.
		rname := ruleByID[f.RuleID]
		sastFindings = append(sastFindings, sast.Finding{
			RuleID:      f.RuleID,
			Message:     f.Message,
			ArtifactURI: f.ArtifactURI,
			Severity:    f.Severity,
			Level:       f.Level,
			Fingerprint: f.Fingerprint,
			Metadata: &sast.RuleMetadata{
				ID:       f.RuleID,
				Name:     rname,
				Severity: f.Severity,
				Kind:     "license",
				Tags:     f.Tags,
			},
		})
	}

	sarifLog := sast.BuildSARIF(sastFindings, sastRules, version)

	apiFindings := make([]vdb.CliSARIFFinding, 0, len(findings))
	memRecords := loadMemoryRecordsForSARIF(gitctx.Collect(rootPath))
	// License findings are package-level (no source line), so no snippet capture.
	_ = snippetContext
	for _, f := range findings {
		mem := memHitForRule(memRecords, f.RuleID)
		apiFindings = append(apiFindings, vdb.CliSARIFFinding{
			RuleID:                 f.RuleID,
			RuleName:               ruleByID[f.RuleID],
			Message:                f.Message,
			Severity:               f.Severity,
			Level:                  f.Level,
			PackagePurl:            f.PackagePurl,
			File:                   f.ArtifactURI,
			Fingerprint:            f.Fingerprint,
			Tags:                   f.Tags,
			SARIFGuid:              f.Fingerprint,
			MemoryVexStatus:        mem.Status,
			MemoryVexJustification: mem.Justification,
			MemoryVexAction:        mem.ActionResponse,
		})
	}

	gitCtx := gitctx.Collect(rootPath)
	env := envForCliWithGit(gitCtx)
	env.ToolMetadata = &vdb.CliSBOMToolMetadata{
		ToolName:    "Vulnetix License",
		ToolVersion: version,
		ToolVendor:  "Vulnetix",
		ToolHash:    commit,
	}
	resp, err := client.CliLicense(env, vdb.CliSARIFRequest{
		SARIF:    sarifLogToMap(sarifLog),
		Findings: apiFindings,
	})
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "  /v2/cli.license submit failed: %v\n", err)
		}
		return
	}
	if resp == nil || resp.Data.IngestionSnapshot == nil {
		return
	}
	if !silent {
		fmt.Fprintf(os.Stderr, "License snapshot: %s\n", resp.Data.IngestionSnapshot.URL)
	}
	reportScanFinalization(resp.Data.IngestionSnapshot.Uuid, nil, nil, gitCtx, gitctx.CollectSystemInfo())
}

// captureSnippet reads the affected source span plus surrounding context for a
// finding that has a file + line. snippetContext semantics:
//   - 0  → capture disabled (returns "")
//   - >0 → that many non-empty surrounding lines on each side
//   - <0 → dynamic: 3 surrounding lines when the affected span is < 10 lines, else 5
//
// Blank/whitespace-only lines are skipped when counting context but kept in the
// emitted text so line numbers stay aligned. Returns the snippet plus the actual
// first/last 1-based line numbers captured.
func captureSnippet(rootPath, file string, startLine, endLine, snippetContext int) (string, int, int) {
	if snippetContext == 0 || file == "" || startLine <= 0 {
		return "", 0, 0
	}
	if endLine < startLine {
		endLine = startLine
	}
	context := snippetContext
	if context < 0 {
		if endLine-startLine+1 < 10 {
			context = 3
		} else {
			context = 5
		}
	}

	path := file
	if !filepath.IsAbs(path) && rootPath != "" {
		path = filepath.Join(rootPath, file)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, 0
	}
	lines := strings.Split(string(data), "\n")
	n := len(lines)
	if startLine > n {
		return "", 0, 0
	}
	if endLine > n {
		endLine = n
	}

	top := startLine
	for cnt := 0; top > 1 && cnt < context; {
		top--
		if strings.TrimSpace(lines[top-1]) != "" {
			cnt++
		}
	}
	bot := endLine
	for cnt := 0; bot < n && cnt < context; {
		bot++
		if strings.TrimSpace(lines[bot-1]) != "" {
			cnt++
		}
	}
	return strings.Join(lines[top-1:bot], "\n"), top, bot
}

func severityToLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}
