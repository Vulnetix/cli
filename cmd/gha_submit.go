package cmd

// Per-file publishing for `vulnetix gha upload`.
//
// Every file inside a workflow artifact is classified, validated, decomposed and
// then posted to the typed /v2/cli.* endpoint that matches what it is. That is
// the whole point of this file: the previous implementation posted opaque bytes
// to a blob endpoint and hoped something downstream would make sense of them,
// which produced no ScannerRun and no IngestionSnapshot for any third-party
// scanner, ever.
//
// Validation runs here as well as on the server. The server's copy is the one
// that decides what gets stored; this one exists so a broken report is named,
// with a reason, in the job that produced it — a zero-byte file from
// `tool > out.sarif || true` used to surface only as an opaque HTTP error.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	cyclonedx "github.com/Vulnetix/vdb-cyclonedx"
	"github.com/Vulnetix/vdb-sca-match/sarif"

	"github.com/vulnetix/cli/v3/internal/upload"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// ghaMaxResults is the server's per-request cap; larger reports are chunked.
const ghaMaxResults = 50000

// ghaFileResult is one file's outcome, and the element type of the --json
// artifacts array. The original three fields (name, file, status) and pipelineId
// are retained verbatim so existing consumers of that output keep working.
type ghaFileResult struct {
	Name       string `json:"name"`
	File       string `json:"file"`
	PipelineID string `json:"pipelineId,omitempty"`
	Status     string `json:"status"` // uploaded | duplicate | skipped | error
	Error      string `json:"error,omitempty"`
	Reason     string `json:"reason,omitempty"`

	Format      string `json:"format,omitempty"`
	Category    string `json:"category,omitempty"`
	CategoryWhy string `json:"categoryWhy,omitempty"`
	Tool        string `json:"tool,omitempty"`
	ToolVersion string `json:"toolVersion,omitempty"`
	Findings    int    `json:"findings,omitempty"`
	Suppressed  int    `json:"suppressed,omitempty"`

	SnapshotUuid string `json:"snapshotUuid,omitempty"`
	SnapshotURL  string `json:"snapshotUrl,omitempty"`
}

// ghaSubmitter holds everything the per-file publishers need.
type ghaSubmitter struct {
	client *vdb.Client
	env    vdb.CliEnv
	ctx    context.Context

	// dryRun classifies, validates and reports without sending anything.
	// --strict is not held here: it only reclassifies a skip as a failure in the
	// final tally, which is the caller's business, not the per-file publisher's.
	dryRun bool

	logf  func(format string, args ...any)
	warnf func(format string, args ...any)
}

// publishFile classifies one extracted file and routes it to the endpoint that
// matches its format.
func (s *ghaSubmitter) publishFile(artifactName, path string) ghaFileResult {
	fileName := filepath.Base(path)
	res := ghaFileResult{Name: artifactName, File: fileName}

	data, err := os.ReadFile(path)
	if err != nil {
		res.Status, res.Error = "error", fmt.Sprintf("read %s: %v", fileName, err)
		return res
	}

	format := upload.DetectFormat(path, data)
	res.Format = format

	switch format {
	case "sarif":
		return s.publishSARIF(res, artifactName, data)
	case "cyclonedx":
		return s.publishCycloneDX(res, artifactName, data)
	case "spdx":
		return s.publishSPDX(res, artifactName, data)
	default:
		// Workflow artifacts routinely carry logs, junit XML and stray text
		// files. Failing a publish job over a README would be a regression in
		// usability, so these are skipped with a stated reason (--strict turns
		// them back into failures).
		res.Status = "skipped"
		res.Reason = fmt.Sprintf("not a SARIF or SBOM document (detected %q)", format)
		s.logf("  %s/%s skipped: %s", artifactName, fileName, res.Reason)
		return res
	}
}

// publishSARIF validates, decomposes and posts a SARIF document to the
// third-party route for its inferred category.
func (s *ghaSubmitter) publishSARIF(res ghaFileResult, artifactName string, data []byte) ghaFileResult {
	log, report := sarif.ValidateBytes(data, ghaMaxResults)
	if text := report.String(); text != "" {
		for _, line := range strings.Split(text, "\n") {
			s.warnf("  %s/%s %s", artifactName, res.File, line)
		}
	}
	if report.HasErrors() {
		res.Status = "error"
		res.Error = firstErrorLine(report)
		return res
	}

	findings, sum := sarif.Decompose(log, sarif.DecomposeOptions{
		// The GitHub artifact name is the strongest category signal available:
		// the workflow already names these "trivy-fs" and "trivy-config", which
		// is the only place Trivy's three scan modes are distinguished.
		Hint:       artifactName,
		RootPath:   s.workspace(),
		MaxResults: ghaMaxResults,
	})

	res.Category = string(sum.Category)
	res.CategoryWhy = sum.CategoryWhy
	res.Tool = sum.Tool.Name
	res.ToolVersion = sum.Tool.Version
	res.Findings = len(findings)
	res.Suppressed = sum.Suppressed

	s.logf("  %s/%s -> %s", artifactName, res.File, sum.String())

	// A report this CLI produced was already persisted by the scan that produced
	// it — `vulnetix sast` posts to /v2/cli.sast before its SARIF is ever
	// uploaded as an artifact. vulnetix.yml's publish job collects those same
	// artifacts, so republishing here would create a second ScannerRun for every
	// first-party scan and double every finding count.
	if isVulnetixOwnTool(sum.Tool.Name) {
		res.Status = "skipped"
		res.Reason = "produced by Vulnetix's own scanner; already published by the scan itself"
		s.logf("  %s/%s skipped: %s", artifactName, res.File, res.Reason)
		return res
	}

	if sum.Category == "" {
		res.Status = "skipped"
		res.Reason = fmt.Sprintf("could not classify %q into a scan category", sum.Tool.Name)
		s.warnf("  %s/%s skipped: %s", artifactName, res.File, res.Reason)
		return res
	}
	if sum.Tool.Name == "" {
		res.Status = "error"
		res.Error = "SARIF declares no runs[].tool.driver.name; findings cannot be attributed"
		return res
	}

	attribution := &vdb.CliToolAttribution{
		ToolName:       sum.Tool.Name,
		ToolVersion:    sum.Tool.Version,
		Vendor:         sum.Tool.Organization,
		Source:         "github-actions",
		ArtifactName:   artifactName,
		FileName:       res.File,
		Format:         "sarif",
		InformationURI: sum.Tool.InformationURI,
		AnalysisKey:    s.analysisKey(sum.Tool.Name),
	}

	if s.dryRun {
		res.Status = "uploaded"
		res.Reason = "dry run; nothing was sent"
		return res
	}

	snapshotUuid, snapshotURL, err := s.postSARIFChunks(log, sum.Category, attribution)
	if err != nil {
		res.Status, res.Error = "error", err.Error()
		return res
	}
	res.Status = "uploaded"
	res.SnapshotUuid = snapshotUuid
	res.SnapshotURL = snapshotURL
	res.PipelineID = snapshotUuid
	return res
}

// postSARIFChunks sends the document, splitting large ones so no single request
// exceeds the server's body limit. Chunk 0 creates the run and snapshot; the
// rest append under the uuid it returned.
//
// Unlike the first-party scan path, a failure on any chunk fails the file.
// Silently landing half a scanner's findings is exactly the class of quiet
// data loss this rewrite exists to remove.
func (s *ghaSubmitter) postSARIFChunks(log *sarif.Log, category sarif.Category, attribution *vdb.CliToolAttribution) (string, string, error) {
	chunks := chunkGHASARIF(log)
	snapshotUuid, snapshotURL := "", ""

	for i, ch := range chunks {
		// No typed findings: the server derives them from the document, and for
		// a relayed third-party report the client has nothing the document does
		// not already say. Sending both invites the two to disagree.
		req := vdb.CliSARIFRequest{
			SARIF:       ch.doc,
			Attribution: attribution,
		}
		if snapshotUuid != "" {
			req.IngestionSnapshotUuid = snapshotUuid
		} else if i > 0 {
			// Chunk 0 persisted nothing (community credential, or the server
			// declined). There is no snapshot to anchor to, so stop rather than
			// mint one run per chunk.
			return "", "", fmt.Errorf("chunk 0 returned no snapshot to append to")
		}

		resp, err := s.client.CliThirdPartySARIF(s.ctx, s.env, category, req)
		if err != nil {
			if isCli404(err) {
				return "", "", fmt.Errorf("server does not support /v2/cli.%s (upgrade vdb-api): %w", category.Route(), err)
			}
			return "", "", fmt.Errorf("chunk %d/%d: %w", i+1, len(chunks), err)
		}
		if i == 0 && resp != nil && resp.Data.IngestionSnapshot != nil {
			snapshotUuid = resp.Data.IngestionSnapshot.Uuid
			snapshotURL = resp.Data.IngestionSnapshot.URL
		}
	}
	return snapshotUuid, snapshotURL, nil
}

// ghaChunk is one request's worth of a split SARIF submission.
//
// Only the document travels. The server re-decomposes whatever document it
// receives and treats its own result as authoritative, so a chunk must carry
// exactly the results it is claiming — no more. Sending the whole document with
// a subset of typed findings would make the server persist every finding on
// chunk 0 and then persist them again as each later chunk appended its share.
type ghaChunk struct {
	doc     map[string]any
	results int
}

// chunkGHASARIF splits a document into requests that stay under the server's
// body limit, by partitioning its results.
//
// Rule descriptors ride chunk 0 only: the append path bumps the result count but
// never recounts rules, so the create call has to see the full rule set, and
// resending megabytes of identical rules per chunk would consume the budget the
// results need. Every chunk keeps its runs' tool driver, because attribution is
// resolved per request and a chunk with no tool name is rejected.
func chunkGHASARIF(log *sarif.Log) []ghaChunk {
	if log == nil || len(log.Runs) == 0 {
		empty, _ := sarif.ToMap(&sarif.Log{Version: "2.1.0"})
		return []ghaChunk{{doc: empty}}
	}

	// Flatten to (run index, result) so a chunk can span runs while still
	// reconstructing each result under the run it came from.
	type ref struct {
		run int
		res sarif.Result
	}
	var refs []ref
	for ri := range log.Runs {
		for _, r := range log.Runs[ri].Results {
			refs = append(refs, ref{run: ri, res: r})
		}
	}
	if len(refs) == 0 {
		doc, _ := sarif.ToMap(log)
		return []ghaChunk{{doc: doc}}
	}

	// build renders one chunk: the original runs, carrying only this chunk's
	// results, with rules kept only on the first.
	build := func(group []ref, first bool) ghaChunk {
		out := &sarif.Log{Schema: log.Schema, Version: log.Version, Runs: make([]sarif.Run, len(log.Runs))}
		for ri := range log.Runs {
			run := log.Runs[ri]
			run.Results = nil
			if !first {
				run.Tool.Driver.Rules = nil
				for ei := range run.Tool.Extensions {
					run.Tool.Extensions[ei].Rules = nil
				}
				run.Taxonomies = nil
				run.Artifacts = nil
			}
			out.Runs[ri] = run
		}
		for _, r := range group {
			out.Runs[r.run].Results = append(out.Runs[r.run].Results, r.res)
		}
		doc, err := sarif.ToMap(out)
		if err != nil {
			doc = map[string]any{"version": "2.1.0", "runs": []any{}}
		}
		return ghaChunk{doc: doc, results: len(group)}
	}

	var chunks []ghaChunk
	var cur []ref
	curBytes := 0
	flush := func() {
		if len(cur) == 0 {
			return
		}
		chunks = append(chunks, build(cur, len(chunks) == 0))
		cur, curBytes = nil, 0
	}

	for _, r := range refs {
		size := 512 // base per-result overhead
		if b, err := json.Marshal(r.res); err == nil {
			size = len(b)
		}
		if len(cur) > 0 && (curBytes+size > sarifChunkByteBudget || len(cur) >= sarifChunkMaxFindings) {
			flush()
		}
		cur = append(cur, r)
		curBytes += size
	}
	flush()
	return chunks
}

// publishCycloneDX extracts the package inventory from a third-party SBOM and
// submits it through the SCA path, so a syft or trivy SBOM produces the same
// Dependency, Finding and IngestionSnapshot rows a `vulnetix sca` run does.
func (s *ghaSubmitter) publishCycloneDX(res ghaFileResult, artifactName string, data []byte) ghaFileResult {
	bom, err := cyclonedx.ParseCDX(data)
	if err != nil {
		res.Status, res.Error = "error", fmt.Sprintf("invalid CycloneDX: %v", err)
		return res
	}

	meta := cyclonedx.ExtractToolMeta(bom)
	toolName := firstNonBlank(meta.ToolName, artifactName)
	res.Tool = toolName
	res.ToolVersion = meta.ToolVersion
	res.Category = string(sarif.CategorySCA)
	res.CategoryWhy = "format:cyclonedx"

	// Same reasoning as the SARIF path: `vulnetix sca` already posted this
	// inventory to /v2/cli.sca before writing .vulnetix/sbom.cdx.json.
	if isVulnetixOwnTool(meta.ToolName) {
		res.Status = "skipped"
		res.Reason = "produced by Vulnetix's own scanner; already published by the scan itself"
		s.logf("  %s/%s skipped: %s", artifactName, res.File, res.Reason)
		return res
	}

	packages, skipped := cdxPackages(bom)
	res.Findings = len(packages)

	s.logf("  %s/%s -> SCA (format:cyclonedx) tool=%s %s components=%d purls=%d",
		artifactName, res.File, orUnknown(toolName), meta.ToolVersion, len(bom.Components), len(packages))
	if skipped > 0 {
		s.warnf("  %s/%s: %d component(s) carry no purl and were skipped", artifactName, res.File, skipped)
	}

	if len(packages) == 0 {
		res.Status = "skipped"
		res.Reason = "no components with a package URL"
		return res
	}
	if s.dryRun {
		res.Status = "uploaded"
		res.Reason = "dry run; nothing was sent"
		return res
	}

	return s.postSCA(res, packages, &vdb.CliToolAttribution{
		ToolName:     toolName,
		ToolVersion:  meta.ToolVersion,
		Vendor:       meta.ToolVendor,
		Source:       "github-actions",
		ArtifactName: artifactName,
		FileName:     res.File,
		Format:       "cyclonedx",
		AnalysisKey:  s.analysisKey(toolName),
	})
}

// publishSPDX does the same for an SPDX document, reading purls out of each
// package's externalRefs.
func (s *ghaSubmitter) publishSPDX(res ghaFileResult, artifactName string, data []byte) ghaFileResult {
	doc, err := parseSPDXPackages(data)
	if err != nil {
		res.Status, res.Error = "error", fmt.Sprintf("invalid SPDX: %v", err)
		return res
	}

	toolName := firstNonBlank(doc.creatorTool, artifactName)
	res.Tool = toolName
	res.Category = string(sarif.CategorySCA)
	res.CategoryWhy = "format:spdx"
	res.Findings = len(doc.packages)

	s.logf("  %s/%s -> SCA (format:spdx) tool=%s packages=%d purls=%d",
		artifactName, res.File, orUnknown(toolName), doc.totalPackages, len(doc.packages))

	if len(doc.packages) == 0 {
		res.Status = "skipped"
		res.Reason = "no packages with a package URL"
		return res
	}
	if s.dryRun {
		res.Status = "uploaded"
		res.Reason = "dry run; nothing was sent"
		return res
	}

	return s.postSCA(res, doc.packages, &vdb.CliToolAttribution{
		ToolName:     toolName,
		Source:       "github-actions",
		ArtifactName: artifactName,
		FileName:     res.File,
		Format:       "spdx",
		AnalysisKey:  s.analysisKey(toolName),
	})
}

// postSCA submits a package inventory to /v2/cli.sca, chunking purls the way the
// first-party SCA path does.
func (s *ghaSubmitter) postSCA(res ghaFileResult, packages []vdb.CliPackageEntry, attribution *vdb.CliToolAttribution) ghaFileResult {
	env := s.env
	env.ToolMetadata = &vdb.CliSBOMToolMetadata{
		ToolName:    attribution.ToolName,
		ToolVersion: attribution.ToolVersion,
		ToolVendor:  attribution.Vendor,
	}

	snapshotUuid, snapshotURL := "", ""
	for start := 0; start < len(packages); start += ghaSCAChunkSize {
		end := min(start+ghaSCAChunkSize, len(packages))
		batch := packages[start:end]

		purls := make([]string, 0, len(batch))
		for _, p := range batch {
			purls = append(purls, p.Purl)
		}

		req := vdb.CliSCARequest{
			Purls:       purls,
			Packages:    batch,
			Attribution: attribution,
		}
		if snapshotUuid != "" {
			req.IngestionSnapshotUuid = snapshotUuid
		} else if start > 0 {
			res.Status = "error"
			res.Error = "first batch returned no snapshot to append to"
			return res
		}

		resp, err := s.client.CliSCAWithContext(s.ctx, env, req)
		if err != nil {
			res.Status = "error"
			res.Error = fmt.Sprintf("packages %d-%d: %v", start+1, end, err)
			return res
		}
		if start == 0 && resp != nil && resp.Data.IngestionSnapshot != nil {
			snapshotUuid = resp.Data.IngestionSnapshot.Uuid
			snapshotURL = resp.Data.IngestionSnapshot.URL
		}
	}

	res.Status = "uploaded"
	res.SnapshotUuid = snapshotUuid
	res.SnapshotURL = snapshotURL
	res.PipelineID = snapshotUuid
	return res
}

// ghaSCAChunkSize matches the first-party SCA path's batch size, which the
// server is tuned for.
const ghaSCAChunkSize = 25

// cdxPackages turns CycloneDX components into the SCA package entries, and
// reports how many were dropped for lacking a purl.
func cdxPackages(bom *cyclonedx.CDXBom) ([]vdb.CliPackageEntry, int) {
	// A component may legitimately appear twice (two manifests, same dependency);
	// the server keys on purl, so collapse here rather than sending duplicates.
	seen := make(map[string]struct{}, len(bom.Components))
	out := make([]vdb.CliPackageEntry, 0, len(bom.Components))
	skipped := 0

	for _, c := range bom.Components {
		purl := strings.TrimSpace(c.Purl)
		if purl == "" {
			skipped++
			continue
		}
		if _, dup := seen[purl]; dup {
			continue
		}
		seen[purl] = struct{}{}

		entry := vdb.CliPackageEntry{
			Purl:      purl,
			Name:      c.Name,
			Version:   c.Version,
			Ecosystem: cyclonedx.ExtractEcosystem(purl),
			Scope:     c.Scope,
		}
		for _, h := range c.Hashes {
			if h.Alg != "" && h.Content != "" {
				entry.Checksums = append(entry.Checksums, vdb.CliPackageChecksum{Alg: h.Alg, Value: h.Content})
			}
		}
		out = append(out, entry)
	}
	return out, skipped
}

// spdxDoc is the slice of an SPDX document this path needs.
type spdxDoc struct {
	creatorTool   string
	packages      []vdb.CliPackageEntry
	totalPackages int
}

// parseSPDXPackages reads package identities out of an SPDX 2.x JSON document.
// Package URLs live in externalRefs entries of category PACKAGE-MANAGER / type
// purl; a package without one cannot be matched and is dropped.
func parseSPDXPackages(data []byte) (*spdxDoc, error) {
	var raw struct {
		CreationInfo struct {
			Creators []string `json:"creators"`
		} `json:"creationInfo"`
		Packages []struct {
			Name         string `json:"name"`
			VersionInfo  string `json:"versionInfo"`
			ExternalRefs []struct {
				ReferenceCategory string `json:"referenceCategory"`
				ReferenceType     string `json:"referenceType"`
				ReferenceLocator  string `json:"referenceLocator"`
			} `json:"externalRefs"`
			Checksums []struct {
				Algorithm     string `json:"algorithm"`
				ChecksumValue string `json:"checksumValue"`
			} `json:"checksums"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	doc := &spdxDoc{totalPackages: len(raw.Packages)}
	for _, creator := range raw.CreationInfo.Creators {
		if tool, ok := strings.CutPrefix(creator, "Tool: "); ok {
			doc.creatorTool = strings.TrimSpace(tool)
			break
		}
	}

	seen := make(map[string]struct{}, len(raw.Packages))
	for _, p := range raw.Packages {
		purl := ""
		for _, ref := range p.ExternalRefs {
			if strings.EqualFold(ref.ReferenceType, "purl") &&
				strings.EqualFold(strings.ReplaceAll(ref.ReferenceCategory, "_", "-"), "PACKAGE-MANAGER") {
				purl = strings.TrimSpace(ref.ReferenceLocator)
				break
			}
		}
		if purl == "" {
			continue
		}
		if _, dup := seen[purl]; dup {
			continue
		}
		seen[purl] = struct{}{}

		entry := vdb.CliPackageEntry{
			Purl:      purl,
			Name:      p.Name,
			Version:   p.VersionInfo,
			Ecosystem: cyclonedx.ExtractEcosystem(purl),
		}
		for _, c := range p.Checksums {
			if c.Algorithm != "" && c.ChecksumValue != "" {
				entry.Checksums = append(entry.Checksums, vdb.CliPackageChecksum{Alg: c.Algorithm, Value: c.ChecksumValue})
			}
		}
		doc.packages = append(doc.packages, entry)
	}
	return doc, nil
}

// analysisKey identifies one tool's report within one workflow run attempt.
// Re-publishing the same key reuses the existing ScannerRun rather than doubling
// every count, which matters because the publish job runs with `if: always()`
// and manual re-runs are routine.
func (s *ghaSubmitter) analysisKey(toolName string) string {
	ci := s.env.CI
	if ci == nil || ci.RunID == 0 || toolName == "" {
		return ""
	}
	attempt := ci.RunAttempt
	if attempt == 0 {
		attempt = 1
	}
	return fmt.Sprintf("gha:%d:%d:%s", ci.RunID, attempt, toolName)
}

// workspace is the root SARIF file paths are relative to.
func (s *ghaSubmitter) workspace() string {
	if s.env.CI != nil && s.env.CI.Workspace != "" {
		return s.env.CI.Workspace
	}
	if s.env.Git != nil {
		return s.env.Git.RepoRoot
	}
	return ""
}

// firstErrorLine returns the first fatal diagnostic, for the compact --json
// error field. The full report has already been logged.
func firstErrorLine(report sarif.Report) string {
	for _, d := range report.Errors() {
		if d.Hint != "" {
			return d.Message + " (" + d.Hint + ")"
		}
		return d.Message
	}
	return "validation failed"
}

// isVulnetixOwnTool reports whether a report was produced by Vulnetix's own
// scanners rather than by a third-party tool.
//
// Those reports arrive here because vulnetix.yml uploads .vulnetix/*.sarif and
// *.cdx.json as workflow artifacts, and this command collects every artifact in
// the run. They must not be republished: each was already persisted by the
// subcommand that produced it, and a second submission would mint a duplicate
// ScannerRun and double the finding counts.
//
// Matching is on the producer name the writers actually emit —
// sast.BuildSARIF sets the driver to "vulnetix", and the SCA/containers paths
// set tool metadata to "Vulnetix SCA", "Vulnetix Malscan", "vulnetix-containers"
// and so on.
func isVulnetixOwnTool(toolName string) bool {
	n := strings.ToLower(strings.TrimSpace(toolName))
	return n == "vulnetix" || strings.HasPrefix(n, "vulnetix ") || strings.HasPrefix(n, "vulnetix-")
}

func firstNonBlank(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "unknown"
	}
	return s
}
