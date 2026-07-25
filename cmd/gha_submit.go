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
	dryRun bool
	// strict promotes skipped files to failures.
	strict bool

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

	snapshotUuid, snapshotURL, err := s.postSARIFChunks(log, findings, sum.Category, attribution)
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
func (s *ghaSubmitter) postSARIFChunks(log *sarif.Log, findings []sarif.Finding, category sarif.Category, attribution *vdb.CliToolAttribution) (string, string, error) {
	chunks := chunkGHAFindings(log, findings)
	snapshotUuid, snapshotURL := "", ""

	for i, ch := range chunks {
		req := vdb.CliSARIFRequest{
			SARIF:       ch.doc,
			Findings:    ch.findings,
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
type ghaChunk struct {
	doc      map[string]any
	findings []vdb.CliSARIFFinding
}

// chunkGHAFindings splits a decomposed document into requests that stay under
// the server's body limit.
//
// Rule descriptors ride chunk 0 only: the append path bumps the result count but
// never recounts rules, so the create call has to see the full rule set.
func chunkGHAFindings(log *sarif.Log, findings []sarif.Finding) []ghaChunk {
	typed := make([]vdb.CliSARIFFinding, len(findings))
	for i, f := range findings {
		typed[i] = vdb.CliSARIFFinding{Finding: f}
	}

	fullDoc, err := sarif.ToMap(log)
	if err != nil {
		fullDoc = map[string]any{"version": "2.1.0", "runs": []any{}}
	}
	if len(typed) == 0 {
		return []ghaChunk{{doc: fullDoc}}
	}

	var chunks []ghaChunk
	var cur []vdb.CliSARIFFinding
	curBytes := 0
	flush := func() {
		if len(cur) == 0 {
			return
		}
		doc := fullDoc
		if len(chunks) > 0 {
			// Chunks after the first carry a stub document: the archived copy
			// and the rule descriptors were stored with chunk 0, and resending
			// megabytes of identical rules per chunk would burn the budget the
			// findings need.
			doc = map[string]any{"version": "2.1.0", "runs": []any{}}
		}
		chunks = append(chunks, ghaChunk{doc: doc, findings: cur})
		cur, curBytes = nil, 0
	}

	for i := range typed {
		size := 256 // base per-finding overhead
		if b, err := json.Marshal(typed[i]); err == nil {
			size = len(b)
		}
		if len(cur) > 0 && (curBytes+size > sarifChunkByteBudget || len(cur) >= sarifChunkMaxFindings) {
			flush()
		}
		cur = append(cur, typed[i])
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
