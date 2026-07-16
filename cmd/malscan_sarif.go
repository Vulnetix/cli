package cmd

// SARIF assembly + upload for `malscan`. The on-disk .vulnetix/malscan.sarif and
// the /v2/cli.malscan payload are both built from the unified malscanFinding set:
// the file reuses the shared sast.BuildSARIF builder (adapting findings into
// sast.Finding/RuleMetadata, exactly like postLicenseSARIF), with the host env
// injected into the run properties; the upload sends typed findings + IOC
// samples, chunked to stay under the server's 8 MiB body cap.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/internal/sast"
	"github.com/vulnetix/cli/v3/pkg/auth"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// malscan upload budgets — kept well under the server's 8 MiB body cap. Findings
// chunk by byte budget; IOC samples (which carry file content) ride chunk 0 only,
// capped both in count and aggregate bytes so a single request never overflows.
const (
	malscanFindingChunkBytes = 3 << 20 // 3 MiB of typed findings per request
	malscanFindingChunkMax   = 2000
	malscanMaxUploadIOCs     = 200
	malscanIOCSampleBudget   = 4 << 20 // 4 MiB aggregate sample bytes on chunk 0
)

// buildMalscanSARIFBytes renders the result as an indented SARIF 2.1.0 document,
// with the host env + git context embedded in the run properties so the evidence
// is self-describing.
func buildMalscanSARIFBytes(res *malscanResult, root string, gitCtx *gitctx.GitContext) ([]byte, error) {
	sastFindings, rules := malscanToSAST(res)
	log := sast.BuildSARIF(sastFindings, rules, version)
	doc := sarifLogToMap(log)
	injectMalscanRunProperties(doc, res, root, gitCtx)
	return json.MarshalIndent(doc, "", "  ")
}

// malscanToSAST adapts the unified findings into the sast builder's input types.
func malscanToSAST(res *malscanResult) ([]sast.Finding, []sast.RuleMetadata) {
	findings := make([]sast.Finding, 0, len(res.Findings))
	ruleSeen := map[string]bool{}
	var rules []sast.RuleMetadata
	for _, f := range res.Findings {
		findings = append(findings, sast.Finding{
			RuleID:      f.RuleID,
			Message:     malscanMessage(f),
			ArtifactURI: f.File,
			Severity:    f.Severity,
			Level:       f.Level,
			StartLine:   f.StartLine,
			EndLine:     f.EndLine,
			Snippet:     f.Snippet,
			Fingerprint: f.Fingerprint,
			Metadata: &sast.RuleMetadata{
				ID:          f.RuleID,
				Name:        f.Title,
				Description: f.Description,
				Severity:    f.Severity,
				Level:       f.Level,
				Kind:        "malware",
				CWE:         f.CWEs,
				Tags:        f.Tags,
			},
		})
		if !ruleSeen[f.RuleID] {
			ruleSeen[f.RuleID] = true
			rules = append(rules, sast.RuleMetadata{
				ID:          f.RuleID,
				Name:        f.Title,
				Description: f.Description,
				Severity:    f.Severity,
				Level:       f.Level,
				Kind:        "malware",
				CWE:         f.CWEs,
				Tags:        f.Tags,
			})
		}
	}
	return findings, rules
}

// injectMalscanRunProperties stamps host/scan context onto runs[0].properties.
func injectMalscanRunProperties(doc map[string]any, res *malscanResult, root string, gitCtx *gitctx.GitContext) {
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) == 0 {
		return
	}
	run, ok := runs[0].(map[string]any)
	if !ok {
		return
	}
	props := map[string]any{
		"scanRoot":       root,
		"host":           res.Host,
		"filesScanned":   res.FilesScanned,
		"indicatorCount": res.IndicatorCount,
		"malicious":      res.Malicious,
	}
	if len(res.Warnings) > 0 {
		props["warnings"] = res.Warnings
	}
	if gitCtx != nil {
		props["git"] = map[string]any{
			"branch":   gitCtx.CurrentBranch,
			"commit":   gitCtx.CurrentCommit,
			"remotes":  gitCtx.RemoteURLs,
			"dirty":    gitCtx.IsDirty,
			"repoRoot": gitCtx.RepoRootPath,
		}
	}
	run["properties"] = props
	runs[0] = run
	doc["runs"] = runs
}

// uploadMalscan submits the findings + IOC samples to POST /v2/cli.malscan.
// Best-effort: community/unauthenticated callers are skipped (the server does not
// persist their data) and any error is non-fatal — the local SARIF is
// authoritative.
func uploadMalscan(res *malscanResult, gitCtx *gitctx.GitContext) {
	uploadMalscanTo(res, gitCtx, os.Stderr)
}

func uploadMalscanTo(res *malscanResult, gitCtx *gitctx.GitContext, w io.Writer) {
	// Submit whenever malscan actually scanned something — a clean pass (targets
	// scanned, 0 findings) still submits so the backend records a ScannerRun +
	// snapshot (coverage). Nothing scanned (no targets) stays a no-op.
	if res == nil || len(res.Targets) == 0 {
		return
	}
	if w == nil {
		w = io.Discard
	}
	creds, err := auth.LoadCredentials()
	if err != nil || creds == nil || auth.IsCommunity(creds) {
		return
	}
	client := vdb.NewClientFromCredentials(creds)
	client.APIVersion = "/v2"
	if client.HTTPClient != nil {
		client.HTTPClient.Timeout = 180 * time.Second
	}

	env := envForCliWithGit(gitCtx)
	env.ToolMetadata = &vdb.CliSBOMToolMetadata{
		ToolName:    "Vulnetix Malscan",
		ToolVersion: version,
		ToolVendor:  "Vulnetix",
		ToolHash:    commit,
	}

	apiFindings := malscanToAPIFindings(res)
	apiIOCs := malscanToAPIIOCs(res)
	sarifFindings, rules := malscanToSAST(res)

	chunks := chunkMalscanFindings(sarifFindings, apiFindings)
	snapshotUuid := ""
	for i, ch := range chunks {
		sarifLog := sast.BuildSARIF(ch.sast, rules, version)
		req := vdb.CliMalscanRequest{
			SARIF:    sarifLogToMap(sarifLog),
			Findings: ch.api,
		}
		if i == 0 {
			req.IOCs = apiIOCs // samples ride the first chunk
		}
		if snapshotUuid != "" {
			req.IngestionSnapshotUuid = snapshotUuid
		} else if i > 0 {
			break // chunk 0 didn't persist (unauth / server skip); stop
		}
		resp, err := client.CliMalscan(env, req)
		if err != nil {
			if verbose {
				fmt.Fprintf(w, "  /v2/cli.malscan chunk %d/%d submit failed: %v\n", i+1, len(chunks), err)
			}
			if i == 0 {
				return
			}
			continue
		}
		if i == 0 && resp != nil && resp.Data.IngestionSnapshot != nil {
			snapshotUuid = resp.Data.IngestionSnapshot.Uuid
			if !silent && resp.Data.IngestionSnapshot.URL != "" {
				fmt.Fprintf(w, "Malscan snapshot: %s\n", resp.Data.IngestionSnapshot.URL)
			}
		}
	}
}

// malscanToAPIFindings converts the unified findings to the wire shape.
func malscanToAPIFindings(res *malscanResult) []vdb.CliSARIFFinding {
	out := make([]vdb.CliSARIFFinding, 0, len(res.Findings))
	for _, f := range res.Findings {
		out = append(out, vdb.CliSARIFFinding{
			RuleID:           f.RuleID,
			RuleName:         f.Title,
			Description:      f.Description,
			Message:          malscanMessage(f),
			Severity:         f.Severity,
			Level:            f.Level,
			File:             f.File,
			StartLine:        f.StartLine,
			EndLine:          f.EndLine,
			Fingerprint:      f.Fingerprint,
			CWEs:             f.CWEs,
			Tags:             f.Tags,
			SARIFGuid:        f.Fingerprint,
			CodeSnippet:      f.Snippet,
			SnippetStartLine: f.StartLine,
			SnippetEndLine:   f.EndLine,
		})
	}
	return out
}

// malscanToAPIIOCs converts IOCs to the wire shape, base64-encoding samples and
// bounding both the count and aggregate sample bytes (truncation is surfaced via
// the run warnings, never silent).
func malscanToAPIIOCs(res *malscanResult) []vdb.CliMalscanIOC {
	out := make([]vdb.CliMalscanIOC, 0, len(res.IOCs))
	sampleBytes := 0
	for i, ioc := range res.IOCs {
		if i >= malscanMaxUploadIOCs {
			break
		}
		w := vdb.CliMalscanIOC{
			Type:       ioc.Type,
			Value:      ioc.Value,
			Ecosystem:  ioc.Ecosystem,
			FilePath:   ioc.FilePath,
			RuleID:     ioc.RuleID,
			Severity:   ioc.Severity,
			References: ioc.References,
		}
		if ioc.Sample != nil {
			w.SampleSHA256 = ioc.Sample.SHA256
			w.SampleName = ioc.Sample.Name
			if sampleBytes+len(ioc.Sample.Content) <= malscanIOCSampleBudget {
				w.SampleBase64 = base64.StdEncoding.EncodeToString(ioc.Sample.Content)
				sampleBytes += len(ioc.Sample.Content)
			}
		}
		out = append(out, w)
	}
	return out
}

// malscanMessage returns the per-finding message, falling back to the rule
// description when no finding-specific message was set.
func malscanMessage(f malscanFinding) string {
	if f.Message != "" {
		return f.Message
	}
	return f.Description
}

// malscanFindingChunk pairs sast findings with their typed API findings so each
// request's per-chunk SARIF doc is built from the matching subset.
type malscanFindingChunk struct {
	sast []sast.Finding
	api  []vdb.CliSARIFFinding
}

func chunkMalscanFindings(sastFindings []sast.Finding, apiFindings []vdb.CliSARIFFinding) []malscanFindingChunk {
	if len(apiFindings) == 0 {
		return []malscanFindingChunk{{}}
	}
	var chunks []malscanFindingChunk
	var curSast []sast.Finding
	var curAPI []vdb.CliSARIFFinding
	curBytes := 0
	flush := func() {
		if len(curAPI) == 0 {
			return
		}
		chunks = append(chunks, malscanFindingChunk{sast: curSast, api: curAPI})
		curSast, curAPI, curBytes = nil, nil, 0
	}
	for i := range apiFindings {
		sz := 256
		if b, err := json.Marshal(apiFindings[i]); err == nil {
			sz = len(b)
		}
		if len(curAPI) > 0 && (curBytes+sz > malscanFindingChunkBytes || len(curAPI) >= malscanFindingChunkMax) {
			flush()
		}
		curSast = append(curSast, sastFindings[i])
		curAPI = append(curAPI, apiFindings[i])
		curBytes += sz
	}
	flush()
	return chunks
}
