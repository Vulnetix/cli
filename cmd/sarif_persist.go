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

var sarifKinds = []sarifScanKind{
	{kind: "sast", category: "sast", label: "SAST"},
	{kind: "secrets", category: "secrets", label: "Secrets"},
	{kind: "iac", category: "iac", label: "IaC"},
	{kind: "oci", category: "containers", label: "Containers"},
}

// postScanSARIF is the single entry point. Called from scan.go after the local
// SARIF is on disk. Splits findings by rule kind, posts each non-empty kind to
// its matching /v2/cli.<kind> endpoint, and prints the resulting snapshot URLs.
func postScanSARIF(report *sast.SASTReport, gitCtx *gitctx.GitContext, rootPath string, snippetContext int) {
	if report == nil || len(report.Findings) == 0 {
		return
	}
	client := newCliClient()
	if client == nil {
		return
	}
	env := envForCli()
	memRecords := loadMemoryRecordsForSARIF(gitCtx)

	byKind := partitionFindingsByKind(report.Findings, report.Rules)
	for _, sk := range sarifKinds {
		bucket, ok := byKind[sk.kind]
		if !ok || len(bucket.findings) == 0 {
			continue
		}
		submitSARIFKind(client, env, sk, bucket, memRecords, rootPath, snippetContext)
	}
}

// submitSARIFKind builds the SARIF doc for one kind and POSTs it.
func submitSARIFKind(client *vdb.Client, env vdb.CliEnv, sk sarifScanKind, bucket kindBucket, memRecords map[string]memory.FindingRecord, rootPath string, snippetContext int) {
	sarifLog := sast.BuildSARIF(bucket.findings, bucket.rules, version)

	// Make the per-kind tool intent explicit (server is authoritative, but this
	// keeps the env block self-describing): "Vulnetix SAST", "Vulnetix IaC", etc.
	env.ToolMetadata = &vdb.CliSBOMToolMetadata{
		ToolName:    "Vulnetix " + sk.label,
		ToolVersion: version,
		ToolVendor:  "Vulnetix",
		ToolHash:    commit,
	}

	// Convert local findings → API typed findings, enriched with memory.yaml VEX.
	apiFindings := make([]vdb.CliSARIFFinding, 0, len(bucket.findings))
	for _, f := range bucket.findings {
		ruleName := ""
		cwes := []int{}
		tags := []string{}
		if f.Metadata != nil {
			ruleName = f.Metadata.Name
			cwes = append(cwes, f.Metadata.CWE...)
			tags = append(tags, f.Metadata.Tags...)
		}
		mem := memHitForRule(memRecords, f.RuleID)
		snippet, snipStart, snipEnd := captureSnippet(rootPath, f.ArtifactURI, f.StartLine, f.EndLine, snippetContext)
		apiFindings = append(apiFindings, vdb.CliSARIFFinding{
			RuleID:                 f.RuleID,
			RuleName:               ruleName,
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
		})
	}

	req := vdb.CliSARIFRequest{
		SARIF:    sarifLogToMap(sarifLog),
		Findings: apiFindings,
	}

	resp, err := dispatchSARIFRequest(client, env, sk.category, req)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "  /v2/cli.%s submit failed: %v\n", sk.category, err)
		}
		return
	}
	if resp == nil || resp.Data.IngestionSnapshot == nil {
		return
	}
	if !silent {
		fmt.Fprintf(os.Stderr, "%s snapshot: %s\n", sk.label, resp.Data.IngestionSnapshot.URL)
	}
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
	if len(findings) == 0 {
		return
	}

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

	env := envForCli()
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
