package cmd

// tryCliSCA performs the /v2/cli.sca round-trip — the single path to the VDB
// for SCA (there is no legacy per-PURL fallback). It self-heals: each batch is
// retried with backoff, and a batch that keeps failing is split into smaller
// chunks (down to a single PURL) before being recorded as unservable. Returns:
//   - apiServed=true  → caller uses findings/enriched as-is
//   - apiServed=false → the API is genuinely unusable (auth/config/network);
//     the caller surfaces this as an error.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vulnetix/cli/v3/internal/cdx"
	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/internal/license"
	"github.com/vulnetix/cli/v3/internal/memory"
	"github.com/vulnetix/cli/v3/internal/reachability"
	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

const cliSCABatchTimeout = 30 * time.Second

// Self-healing retry/backoff knobs for the cli.sca sender. Declared as vars
// (not consts) so tests can shrink them — the production values stay fixed.
var (
	maxBatchAttempts = 3                      // attempts per request before giving up
	scaBackoffBase   = 500 * time.Millisecond // first backoff step
	scaBackoffMax    = 8 * time.Second        // backoff ceiling
)

const (
	minChunkSize = 1  // a job at this size can no longer be split on failure
	sCAChunkSize = 25 // PURLs per batch; halved adaptively on transient failure
)

// cliSCAGateOptions tells tryCliSCA which per-package gate signals the active
// scan flags need, so the cli.sca round-trip requests them (and only them).
type cliSCAGateOptions struct {
	Cooldown     bool // --cooldown
	VersionLag   bool // --version-lag
	SafeVersions bool // --sca-autofix
	EOL          bool // --block-eol (package-level)
	Malware      bool // --block-malware
}

func tryCliSCA(allPackages []scan.ScopedPackage, manifestGroups []scan.ManifestGroup, licenseByKey map[string]string, gitCtx *gitctx.GitContext, sysInfo *gitctx.SystemInfo, scanPath, toolName string, gateOpts cliSCAGateOptions, w io.Writer) (apiServed bool, findings []scan.VulnFinding, enriched []scan.EnrichedVuln, insights []vdb.CliPackageInsight, snapshotUuid string, snapshotURL string, persisted []vdb.CliFindingResult) {
	if w == nil {
		w = os.Stderr
	}
	if len(allPackages) == 0 {
		return false, nil, nil, nil, "", "", nil
	}

	purls := make([]string, len(allPackages))
	deduped := make(map[string]bool, len(allPackages))
	uniquePurls := make([]string, 0, len(allPackages))
	for i, p := range allPackages {
		pu := cdx.BuildLocalPurl(p.Name, p.Version, p.Ecosystem)
		purls[i] = pu
		if pu == "" || deduped[pu] {
			continue
		}
		deduped[pu] = true
		uniquePurls = append(uniquePurls, pu)
	}
	if len(uniquePurls) == 0 {
		return false, nil, nil, nil, "", "", nil
	}

	// Chunk PURLs to stay well inside CloudFront's 60s origin timeout.
	// Smaller chunks trade a few extra round-trips for predictable latency
	// against vuln-dense fixtures where each PURL may fan out to dozens of
	// CVE rows in the handler.
	chunks := chunkPurls(uniquePurls, sCAChunkSize)

	// One default-visible status line; per-batch progress is verbose-only.
	if !silent {
		fmt.Fprintf(w, "Querying VDB via /v2/cli.sca: %d unique package(s) in %d batch(es)...\n", len(uniquePurls), len(chunks))
	}

	client := newCliClient()
	if client == nil {
		return false, nil, nil, nil, "", "", nil
	}
	if client.HTTPClient != nil {
		client.HTTPClient.Timeout = cliSCABatchTimeout
	}

	env := buildCliEnv(gitCtx, sysInfo)
	if toolName != "" {
		if env.ToolMetadata == nil {
			env.ToolMetadata = &vdb.CliSBOMToolMetadata{}
		}
		env.ToolMetadata.ToolName = toolName
	}
	enrichCliEnvForSCA(&env, scanPath, allPackages, gitCtx)

	// Raw manifest bodies (lockfiles) can be large, so we don't cram them all
	// onto chunk 0 — that would blow the server's 8 MiB request cap. Chunk 0
	// carries metadata-only manifests (creates the CliManifest rows + a stable
	// bundle hash); the raw bodies are spread, size-bounded, across the
	// snapshot-anchored requests (plus extra manifest-only requests if needed),
	// where the server fills in each row's rawArtifactUuid.
	lightEnv := env
	lightEnv.Manifests = stripManifestContent(env.Manifests)
	metaEnv := env
	metaEnv.Manifests = stripManifestContent(env.Manifests)
	bodySlots := packManifestsBySize(env.Manifests, scaManifestByteBudget)

	// Per-PURL Packages list with manifest + chain info. Sent on the chunks that
	// carry purls so each chunk's findings get package context.
	allCliPackages := buildCliPackages(allPackages, manifestGroups, licenseByKey)

	mergedComponents := make([]any, 0, len(uniquePurls))
	mergedVulns := make([]any, 0)
	mergedReach := make([]vdb.CliReachabilityHit, 0)
	mergedInsights := make([]vdb.CliPackageInsight, 0)
	tierObserved := "" // "pro" wins over any spurious community batch
	var anyTierGated bool
	var snapshot *vdb.CliIngestionSnapshot
	var persistedFindings []vdb.CliFindingResult

	// Seed the self-healing job queue. The first PURL chunk is the primary job —
	// it carries the metadata manifests + full package list and creates the
	// run/snapshot. Remaining PURL chunks are discovery jobs; the size-bounded
	// manifest-body slots each ride their own job, anchored to the snapshot once
	// it exists.
	jobs := make([]scaJob, 0, len(chunks)+len(bodySlots))
	for i, c := range chunks {
		jobs = append(jobs, scaJob{purls: c, primary: i == 0, manifestSlot: -1})
	}
	for s := range bodySlots {
		jobs = append(jobs, scaJob{primary: false, manifestSlot: s})
	}
	if len(jobs) == 0 {
		jobs = append(jobs, scaJob{primary: true, manifestSlot: -1})
	}

	buildReq := func(job scaJob) (vdb.CliEnv, vdb.CliSCARequest, bool) {
		req := vdb.CliSCARequest{
			Purls: job.purls,
			Options: vdb.CliSCAOptions{
				IncludeReachability: boolPtrCLI(true),
				IncludeCooldown:     gateOpts.Cooldown,
				IncludeVersionLag:   gateOpts.VersionLag,
				IncludeSafeVersions: gateOpts.SafeVersions,
				IncludeEOL:          gateOpts.EOL,
				IncludeMalware:      gateOpts.Malware,
			},
		}
		if job.primary {
			// Creates the run/snapshot: metadata-only manifests + full package list.
			req.Packages = allCliPackages
			return metaEnv, req, false
		}
		reqEnv := lightEnv
		if snapshot != nil {
			// Append under the primary's run. Carry packages for finding context on
			// jobs that have purls, plus this job's slice of manifest bodies.
			req.IngestionSnapshotUuid = snapshot.Uuid
			if len(job.purls) > 0 {
				req.Packages = allCliPackages
			}
			if job.manifestSlot >= 0 && job.manifestSlot < len(bodySlots) {
				reqEnv.Manifests = bodySlots[job.manifestSlot]
			}
		} else if len(job.purls) == 0 {
			// No snapshot to anchor a manifest-only request; skip it. (Discovery
			// jobs with purls still run for CDX/vuln data.)
			return reqEnv, req, true
		}
		return reqEnv, req, false
	}

	onResult := func(_ scaJob, resp *vdb.CliResponse[vdb.CliSCAResponse]) {
		if resp.Meta.Tier == "pro" {
			tierObserved = "pro"
		}
		if resp.Meta.TierGated["reachability"] {
			anyTierGated = true
		}
		if cs, ok := resp.Data.CycloneDX["components"].([]any); ok {
			mergedComponents = append(mergedComponents, cs...)
		}
		if vs, ok := resp.Data.CycloneDX["vulnerabilities"].([]any); ok {
			mergedVulns = append(mergedVulns, vs...)
		}
		mergedReach = append(mergedReach, resp.Data.Reachability...)
		mergedInsights = append(mergedInsights, resp.Data.PackageInsights...)
		// Capture the snapshot once (the primary job creates it). Findings come
		// back from every job; accumulate them so reachability can correlate
		// findings across the whole scan.
		if snapshot == nil && resp.Data.IngestionSnapshot != nil {
			snapshot = resp.Data.IngestionSnapshot
		}
		persistedFindings = append(persistedFindings, resp.Data.Findings...)
	}

	unservable, anyOK, firstErr := runSCAJobs(client, jobs, buildReq, onResult, w)

	// The v2 endpoint is the only path now: there is no legacy fallback. A total
	// failure means the API is genuinely unusable (auth/config/network), which
	// the caller surfaces as an actionable error.
	if !anyOK {
		if !silent {
			fmt.Fprintf(w, "  /v2/cli.sca all request(s) failed (%v)\n", firstErr)
		}
		return false, nil, nil, nil, "", "", nil
	}
	if len(unservable) > 0 && !silent {
		fmt.Fprintf(w, "  /v2/cli.sca could not retrieve %d package(s) after retries; results omit them\n", len(unservable))
		if verbose {
			for _, p := range unservable {
				fmt.Fprintf(w, "    unservable: %s\n", p)
			}
		}
	}

	// Only show the upgrade note when we *consistently* observed community
	// across every batch. A single Pro response is enough to suppress it —
	// guards against transient replica/cache flaps on the server.
	if anyTierGated && tierObserved != "pro" && !silent {
		fmt.Fprintln(w, "Note: reachability requires Pro / Team / Business / Enterprise — upgrade at https://www.vulnetix.com/pricing")
	}

	merged := map[string]any{
		"bomFormat":       "CycloneDX",
		"specVersion":     "1.6",
		"components":      mergedComponents,
		"vulnerabilities": mergedVulns,
	}
	findings, enriched, _ = scan.SynthesiseFromCDX(merged, allPackages, purls)
	if findings == nil {
		if !silent {
			fmt.Fprintln(w, "  /v2/cli.sca returned no CycloneDX document")
		}
		return false, nil, nil, nil, "", "", nil
	}
	if verbose {
		fmt.Fprintf(w, "  /v2/cli.sca returned %d finding(s) across %d package(s)\n", len(findings), len(uniquePurls))
	}

	// Pro+ tiers: run the returned tree-sitter queries locally so the
	// Reachability column on each finding reflects actual code analysis,
	// not just whether the server delivered queries. Community gets nothing
	// here because the server already returned reachability=nil.
	if len(mergedReach) > 0 {
		runReachabilityForFindings(mergedReach, enriched, scanPath, w)
	}

	// Symbol fallback (all tiers): for any finding the tree-sitter pass
	// didn't verdict, grep local source for affectedRoutines/Files/Modules.
	runSymbolFallback(enriched, scanPath, w)

	// Post reachability evidence back to the server when persistence
	// succeeded. Best-effort: a failure here doesn't break the local scan.
	if snapshot != nil {
		postReachabilityToSnapshot(client, env, snapshot, persistedFindings, enriched, gitCtx, w)
		if !silent {
			fmt.Fprintf(w, "Snapshot: %s\n", snapshot.URL)
		}
	}

	finalSnapshotUuid := ""
	finalSnapshotURL := ""
	if snapshot != nil {
		finalSnapshotUuid = snapshot.Uuid
		finalSnapshotURL = snapshot.URL
	}
	return true, findings, enriched, mergedInsights, finalSnapshotUuid, finalSnapshotURL, persistedFindings
}

// postCliSCABOM persists the package/container inventory to /v2/cli.sca without
// using the response as SCA findings. Container scans use this to create the
// run's SBOM snapshot before posting container SARIF to /v2/cli.containers.
func postCliSCABOM(allPackages []scan.ScopedPackage, manifestGroups []scan.ManifestGroup, licenseByKey map[string]string, gitCtx *gitctx.GitContext, sysInfo *gitctx.SystemInfo, scanPath, toolName string, w io.Writer) (apiServed bool, insights []vdb.CliPackageInsight, snapshotUuid string, snapshotURL string, persisted []vdb.CliFindingResult) {
	if w == nil {
		w = os.Stderr
	}
	if len(allPackages) == 0 {
		return false, nil, "", "", nil
	}

	deduped := make(map[string]bool, len(allPackages))
	uniquePurls := make([]string, 0, len(allPackages))
	for _, p := range allPackages {
		pu := cdx.BuildLocalPurl(p.Name, p.Version, p.Ecosystem)
		if pu == "" || deduped[pu] {
			continue
		}
		deduped[pu] = true
		uniquePurls = append(uniquePurls, pu)
	}
	if len(uniquePurls) == 0 {
		return false, nil, "", "", nil
	}

	client := newCliClient()
	if client == nil {
		return false, nil, "", "", nil
	}
	if client.HTTPClient != nil {
		client.HTTPClient.Timeout = cliSCABatchTimeout
	}

	env := buildCliEnv(gitCtx, sysInfo)
	if env.ToolMetadata == nil {
		env.ToolMetadata = &vdb.CliSBOMToolMetadata{}
	}
	if toolName != "" {
		env.ToolMetadata.ToolName = toolName
	}
	enrichCliEnvForSCA(&env, scanPath, allPackages, gitCtx)

	metaEnv := env
	metaEnv.Manifests = stripManifestContent(env.Manifests)
	lightEnv := env
	lightEnv.Manifests = stripManifestContent(env.Manifests)
	bodySlots := packManifestsBySize(env.Manifests, scaManifestByteBudget)
	allCliPackages := buildCliPackages(allPackages, manifestGroups, licenseByKey)

	chunks := chunkPurls(uniquePurls, sCAChunkSize)
	jobs := make([]scaJob, 0, len(chunks)+len(bodySlots))
	for i, c := range chunks {
		jobs = append(jobs, scaJob{purls: c, primary: i == 0, manifestSlot: -1})
	}
	for s := range bodySlots {
		jobs = append(jobs, scaJob{primary: false, manifestSlot: s})
	}
	if len(jobs) == 0 {
		jobs = append(jobs, scaJob{primary: true, manifestSlot: -1})
	}

	var snapshot *vdb.CliIngestionSnapshot
	var mergedInsights []vdb.CliPackageInsight
	var persistedFindings []vdb.CliFindingResult
	buildReq := func(job scaJob) (vdb.CliEnv, vdb.CliSCARequest, bool) {
		req := vdb.CliSCARequest{
			Purls: job.purls,
			Options: vdb.CliSCAOptions{
				IncludeReachability: boolPtrCLI(false),
			},
		}
		if job.primary {
			req.Packages = allCliPackages
			return metaEnv, req, false
		}
		reqEnv := lightEnv
		if snapshot != nil {
			req.IngestionSnapshotUuid = snapshot.Uuid
			if len(job.purls) > 0 {
				req.Packages = allCliPackages
			}
			if job.manifestSlot >= 0 && job.manifestSlot < len(bodySlots) {
				reqEnv.Manifests = bodySlots[job.manifestSlot]
			}
		} else if len(job.purls) == 0 {
			return reqEnv, req, true
		}
		return reqEnv, req, false
	}
	onResult := func(_ scaJob, resp *vdb.CliResponse[vdb.CliSCAResponse]) {
		if snapshot == nil && resp.Data.IngestionSnapshot != nil {
			snapshot = resp.Data.IngestionSnapshot
		}
		mergedInsights = append(mergedInsights, resp.Data.PackageInsights...)
		persistedFindings = append(persistedFindings, resp.Data.Findings...)
	}

	unservable, anyOK, firstErr := runSCAJobs(client, jobs, buildReq, onResult, w)
	if !anyOK {
		if verbose {
			fmt.Fprintf(w, "  /v2/cli.sca BOM persistence failed (%v)\n", firstErr)
		}
		return false, nil, "", "", nil
	}
	if len(unservable) > 0 && verbose {
		fmt.Fprintf(w, "  /v2/cli.sca BOM persistence omitted %d package(s) after retries\n", len(unservable))
	}
	if snapshot == nil {
		return true, mergedInsights, "", "", persistedFindings
	}
	return true, mergedInsights, snapshot.Uuid, snapshot.URL, persistedFindings
}

// confirmVulnsViaCliSCA re-queries the given packages through /v2/cli.sca in a
// lightweight "confirmation" mode — no reachability, no snapshot/persistence, no
// manifest bodies — and returns the enriched findings. The post-autofix re-scan
// uses it to learn which vulnerabilities remain. It shares the same self-healing
// sender as the primary path (retry, backoff, adaptive chunk-size reduction);
// there is no legacy per-PURL fallback.
//
// It is deliberately conservative: if the API is unreachable or any package
// can't be re-queried after retries, it returns an error rather than an
// incomplete result, so the caller never mistakes "couldn't check" for "fixed".
func confirmVulnsViaCliSCA(allPackages []scan.ScopedPackage) ([]scan.EnrichedVuln, error) {
	if len(allPackages) == 0 {
		return nil, nil
	}
	purls := make([]string, len(allPackages))
	deduped := make(map[string]bool, len(allPackages))
	uniquePurls := make([]string, 0, len(allPackages))
	for i, p := range allPackages {
		pu := cdx.BuildLocalPurl(p.Name, p.Version, p.Ecosystem)
		purls[i] = pu
		if pu == "" || deduped[pu] {
			continue
		}
		deduped[pu] = true
		uniquePurls = append(uniquePurls, pu)
	}
	if len(uniquePurls) == 0 {
		return nil, nil
	}

	client := newCliClient()
	if client == nil {
		return nil, fmt.Errorf("cli.sca confirmation: no API client (missing credentials)")
	}
	if client.HTTPClient != nil {
		client.HTTPClient.Timeout = cliSCABatchTimeout
	}
	env := buildCliEnv(nil, nil)

	jobs := make([]scaJob, 0)
	for _, c := range chunkPurls(uniquePurls, sCAChunkSize) {
		jobs = append(jobs, scaJob{purls: c, primary: false, manifestSlot: -1})
	}

	mergedComponents := make([]any, 0, len(uniquePurls))
	mergedVulns := make([]any, 0)

	buildReq := func(job scaJob) (vdb.CliEnv, vdb.CliSCARequest, bool) {
		return env, vdb.CliSCARequest{
			Purls:   job.purls,
			Options: vdb.CliSCAOptions{IncludeReachability: boolPtrCLI(false)},
		}, false
	}
	onResult := func(_ scaJob, resp *vdb.CliResponse[vdb.CliSCAResponse]) {
		if cs, ok := resp.Data.CycloneDX["components"].([]any); ok {
			mergedComponents = append(mergedComponents, cs...)
		}
		if vs, ok := resp.Data.CycloneDX["vulnerabilities"].([]any); ok {
			mergedVulns = append(mergedVulns, vs...)
		}
	}

	unservable, anyOK, firstErr := runSCAJobs(client, jobs, buildReq, onResult, io.Discard)
	if !anyOK {
		return nil, fmt.Errorf("cli.sca confirmation lookup failed: %w", firstErr)
	}
	if len(unservable) > 0 {
		return nil, fmt.Errorf("cli.sca confirmation could not re-query %d package(s); cannot verify autofix", len(unservable))
	}

	merged := map[string]any{
		"bomFormat":       "CycloneDX",
		"specVersion":     "1.6",
		"components":      mergedComponents,
		"vulnerabilities": mergedVulns,
	}
	_, enriched, _ := scan.SynthesiseFromCDX(merged, allPackages, purls)
	return enriched, nil
}

// buildCliPackages turns parsed ScopedPackages into the per-package metadata
// the server uses to populate FindingIntroducedVia. Each package contributes
// a single chain — `[manifest-derived-root, name@version]` for direct deps
// and `[manifest-derived-root, ..., name@version]` for transitives (chain
// length 2 for transitives is a fidelity loss vs. full upstream-walk, but
// the manifestFile + IsDirect flag still let the server bucket the path).
func buildCliPackages(pkgs []scan.ScopedPackage, manifestGroups []scan.ManifestGroup, licenseByKey map[string]string) []vdb.CliPackageEntry {
	if len(pkgs) == 0 {
		return nil
	}
	out := make([]vdb.CliPackageEntry, 0, len(pkgs))
	for _, p := range pkgs {
		key := fmt.Sprintf("%s@%s", p.Name, p.Version)
		purl := cdx.BuildLocalPurl(p.Name, p.Version, p.Ecosystem)
		scope := p.Scope
		if scope == "" {
			if p.IsDirect {
				scope = "direct"
			} else {
				scope = "transitive"
			}
		}
		chain := introducedViaChain(p, key, manifestGroups)

		entry := vdb.CliPackageEntry{
			Purl:          purl,
			Name:          p.Name,
			Version:       p.Version,
			Ecosystem:     p.Ecosystem,
			ManifestFile:  p.SourceFile,
			Scope:         scope,
			License:       licenseByKey[key],
			IntroducedVia: [][]string{chain},
		}

		if len(p.Checksums) > 0 {
			cs := make([]vdb.CliPackageChecksum, len(p.Checksums))
			for i, c := range p.Checksums {
				cs[i] = vdb.CliPackageChecksum{Alg: c.Alg, Value: c.Value}
			}
			entry.Checksums = cs
		}

		out = append(out, entry)
	}
	return out
}

// introducedViaChain computes the full root→leaf dependency chain for a package
// using the per-ecosystem dependency graph. Direct deps return [key]; transitive
// deps return the real chain from a direct dep when the graph has edges,
// otherwise the reconstructed [<unknown>, key] fallback.
func introducedViaChain(p scan.ScopedPackage, key string, manifestGroups []scan.ManifestGroup) []string {
	if p.IsDirect {
		return []string{key}
	}
	for _, mg := range manifestGroups {
		if mg.Graph == nil || mg.Graph.IsDirect(p.Name) {
			continue
		}
		if path := mg.Graph.FindPath(p.Name); len(path) > 1 {
			// Graph paths are package names; append the version to the leaf so the
			// chain ends with the resolved key the server can match.
			chain := make([]string, len(path))
			copy(chain, path)
			chain[len(chain)-1] = key
			return chain
		}
	}
	return []string{"<unknown>", key}
}

// postReachabilityToSnapshot sends the local tree-sitter + grep-symbol
// reachability evidence to /v2/cli.sca-reachability so the server can:
//   - persist CliReachabilityResult rows
//   - update Triage automatically (UNREACHABLE → not_affected/code_not_reachable;
//     reachable → affected)
//   - upsert OpenVex + VexAnalysis records
//   - merge reachability properties into the S3-stored SBOM
//   - emit a CycloneDX VEX artefact alongside the SBOM
//
// Memory-yaml VEX hints are attached so user-authored decisions win over the
// auto-computed verdict.
// buildReachabilityPayloads turns enriched vulns into CliReachabilityPayload
// rows. It is pure (no side effects, no network) so it is unit-testable.
func buildReachabilityPayloads(enriched []scan.EnrichedVuln, findingByKey map[string]vdb.CliFindingResult, memRecords map[string]memory.FindingRecord) []vdb.CliReachabilityPayload {
	payloads := make([]vdb.CliReachabilityPayload, 0, len(enriched)*2)
	for _, ev := range enriched {
		fkey := ev.CveID + "|" + ev.PackageName + "|" + ev.PackageVer
		finding := findingByKey[fkey]
		memHit := memoryMatchForFinding(memRecords, ev.PackageName, ev.CveID)
		fixedVer := ""
		if ev.Remediation != nil {
			fixedVer = ev.Remediation.FixVersion
		}

		base := vdb.CliReachabilityPayload{
			CveID:                  ev.CveID,
			FindingUuid:            finding.FindingUuid,
			PackageName:            ev.PackageName,
			PackageVersion:         ev.PackageVer,
			Purl:                   finding.Purl,
			Ecosystem:              ev.Ecosystem,
			Severity:               ev.Severity,
			FixedVersion:           fixedVer,
			MemoryVexStatus:        memHit.Status,
			MemoryVexJustification: memHit.Justification,
			MemoryVexAction:        memHit.ActionResponse,
		}

		switch ev.Reachability {
		case "direct", "transitive":
			row := base
			row.Source = "TREE_SITTER"
			row.Verdict = strings.ToUpper(ev.Reachability)
			if ev.AffectedSymbols != nil && len(ev.AffectedSymbols.Routines) > 0 {
				row.MatchedRoutine = ev.AffectedSymbols.Routines[0]
			}
			if len(ev.ReachabilityQueryHashes) > 0 {
				row.QueryHash = ev.ReachabilityQueryHashes[0]
			}
			payloads = append(payloads, row)
		case "semantic":
			if len(ev.SemanticMatches) == 0 {
				break
			}
			for _, m := range ev.SemanticMatches {
				row := base
				row.Source = "SEMANTIC_GREP"
				row.Verdict = "SEMANTIC"
				row.MatchedFile = m.File
				row.MatchedRoutine = m.Symbol
				row.MatchStartLine = m.Line
				payloads = append(payloads, row)
			}
		case "unreachable":
			if !ev.ReachabilityAssessed {
				break
			}
			row := base
			row.Source = "TREE_SITTER"
			row.Verdict = "UNREACHABLE"
			if len(ev.ReachabilityQueryHashes) > 0 {
				row.QueryHash = ev.ReachabilityQueryHashes[0]
			}
			if ev.AffectedSymbols != nil && (len(ev.AffectedSymbols.Routines) > 0 || len(ev.AffectedSymbols.Files) > 0 || len(ev.AffectedSymbols.Modules) > 0) {
				evidence := map[string]any{
					"routines": ev.AffectedSymbols.Routines,
					"files":    ev.AffectedSymbols.Files,
					"modules":  ev.AffectedSymbols.Modules,
				}
				if b, err := json.Marshal(evidence); err == nil {
					row.EvidenceJSON = string(b)
				}
			}
			payloads = append(payloads, row)
		default:
			// Empty / unassessed — emit no row.
		}
	}
	return payloads
}

func postReachabilityToSnapshot(client *vdb.Client, env vdb.CliEnv, snapshot *vdb.CliIngestionSnapshot, persisted []vdb.CliFindingResult, enriched []scan.EnrichedVuln, gitCtx *gitctx.GitContext, w io.Writer) {
	if w == nil {
		w = os.Stderr
	}
	if snapshot == nil || len(enriched) == 0 {
		return
	}

	findingByKey := make(map[string]vdb.CliFindingResult, len(persisted))
	for _, f := range persisted {
		k := f.FindingID + "|" + f.PackageName + "|" + f.PackageVersion
		findingByKey[k] = f
	}

	memRecords := loadMemoryRecords(gitCtx)
	payloads := buildReachabilityPayloads(enriched, findingByKey, memRecords)

	if len(payloads) == 0 {
		return
	}

	resp, err := client.CliSCAReachability(env, vdb.CliSCAReachabilityRequest{
		IngestionSnapshotUuid: snapshot.Uuid,
		Results:               payloads,
	})
	if err != nil {
		if verbose {
			fmt.Fprintf(w, "  reachability post failed: %v\n", err)
		}
		return
	}
	if verbose {
		fmt.Fprintf(w, "  reachability persisted: %d (sbom=%s, vex=%s)\n", resp.Data.Persisted, resp.Data.SBOMUrl, resp.Data.VEXUrl)
	}
}

// memoryHit captures the three VEX-relevant memory fields per finding.
type memoryHit struct {
	Status         string
	Justification  string
	ActionResponse string
}

func loadMemoryRecords(gitCtx *gitctx.GitContext) map[string]memory.FindingRecord {
	if gitCtx == nil || gitCtx.RepoRootPath == "" {
		return nil
	}
	vulnetixDir := filepath.Join(gitCtx.RepoRootPath, ".vulnetix")
	store, err := memory.Load(vulnetixDir)
	if err != nil || store == nil {
		return nil
	}
	return store.Findings
}

func memoryMatchForFinding(records map[string]memory.FindingRecord, packageName, cveID string) memoryHit {
	// Primary key in memory.yaml is the CVE id.
	if r, ok := records[cveID]; ok && strings.EqualFold(r.Package, packageName) {
		return memoryHit{Status: r.Status, Justification: r.Justification, ActionResponse: r.ActionResponse}
	}
	return memoryHit{}
}

// runSymbolFallback covers the everywhere-available lower-efficacy
// reachability path — server-returned routine / file / module names are
// regex-matched against project source. CVEs with hits get
// Reachability="semantic" (this is the "the dep is referenced by name in
// your code" signal — see Semantic Reachability docs). CVEs that the
// tree-sitter pass already verdicted are skipped: we don't want to
// downgrade a higher-confidence label to the semantic fallback.
func runSymbolFallback(enriched []scan.EnrichedVuln, projectRoot string, w io.Writer) {
	if w == nil {
		w = os.Stderr
	}
	inputs := make([]reachability.CveSymbols, 0, len(enriched))
	for _, ev := range enriched {
		if ev.Reachability != "" {
			continue
		}
		if !ev.AffectedSymbols.HasAny() {
			continue
		}
		inputs = append(inputs, reachability.CveSymbols{
			CveID:    ev.CveID,
			Routines: ev.AffectedSymbols.Routines,
			Files:    ev.AffectedSymbols.Files,
			Modules:  ev.AffectedSymbols.Modules,
		})
	}
	if len(inputs) == 0 {
		return
	}

	cwd := projectRoot
	if cwd == "" {
		var err error
		if cwd, err = os.Getwd(); err != nil || cwd == "" {
			return
		}
	}

	if verbose {
		fmt.Fprintf(w, "  running symbol fallback for %d CVE(s) in %s...\n", len(inputs), cwd)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := reachability.MatchAffectedSymbols(ctx, reachability.SymbolMatchRequest{
		ProjectRoot: cwd,
		Inputs:      inputs,
	})
	if err != nil {
		if verbose {
			fmt.Fprintf(w, "  symbol fallback failed: %v\n", err)
		}
		return
	}
	if res == nil || len(res.HitsByCVE) == 0 {
		if verbose {
			fmt.Fprintln(w, "  symbol fallback: no hits")
		}
		return
	}

	for i := range enriched {
		if enriched[i].Reachability != "" {
			continue
		}
		hits, hit := res.HitsByCVE[enriched[i].CveID]
		if !hit {
			continue
		}
		enriched[i].Reachability = "semantic"
		// Stash the file:line hits so printPrettyScanSummary can render
		// them in the Semantic Reachability section.
		enriched[i].SemanticMatches = make([]scan.SemanticMatch, 0, len(hits))
		for _, h := range hits {
			enriched[i].SemanticMatches = append(enriched[i].SemanticMatches, scan.SemanticMatch{
				File:   h.File,
				Line:   h.Line,
				Symbol: h.Symbol,
				Kind:   h.Kind,
			})
		}
	}
	if verbose {
		fmt.Fprintf(w, "  semantic reachability: %d CVE(s) matched in source\n", len(res.HitsByCVE))
	}
}

// runReachabilityForFindings turns the per-CVE tree-sitter queries returned
// by /v2/cli.sca into actual reachability results by running them across the
// project root. CVEs whose queries match → Reachability="transitive"; CVEs
// whose queries run cleanly with zero matches → "unreachable"; CVEs we
// couldn't evaluate stay empty. Direct-mode (per-install-directory) requires
// ScopedPackage routing and lands in a follow-up.
func runReachabilityForFindings(hits []vdb.CliReachabilityHit, enriched []scan.EnrichedVuln, projectRoot string, w io.Writer) {
	if w == nil {
		w = os.Stderr
	}
	if len(hits) == 0 || len(enriched) == 0 {
		return
	}
	cwd := projectRoot
	if cwd == "" {
		var err error
		if cwd, err = os.Getwd(); err != nil || cwd == "" {
			return
		}
	}

	// Dedupe queries by hash so a single S-expression isn't compiled and
	// run multiple times for fixtures where N CVEs share the same query.
	type queryEntry struct {
		query vdb.TreeSitterQuery
		cves  map[string]bool
	}
	byHash := make(map[string]*queryEntry, len(hits))
	for _, h := range hits {
		hash := h.QueryHash
		if hash == "" {
			hash = h.Name + ":" + h.Language
		}
		entry, ok := byHash[hash]
		if !ok {
			entry = &queryEntry{
				query: vdb.TreeSitterQuery{
					VulnID:    h.VulnID,
					Source:    h.Source,
					Language:  h.Language,
					Name:      h.Name,
					QueryText: h.QueryText,
					QueryHash: h.QueryHash,
				},
				cves: map[string]bool{},
			}
			byHash[hash] = entry
		}
		entry.cves[h.VulnID] = true
	}

	queries := make([]vdb.TreeSitterQuery, 0, len(byHash))
	for _, e := range byHash {
		queries = append(queries, e.query)
	}

	if verbose {
		fmt.Fprintf(w, "  running %d reachability query(ies) across %s...\n", len(queries), cwd)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	engine := reachability.NewEngine()
	res, err := reachability.Scan(ctx, engine, reachability.ScanRequest{
		ProjectRoot: cwd,
		Queries:     queries,
		Mode:        reachability.ModeTransitive,
	})
	if err != nil {
		if verbose {
			fmt.Fprintf(w, "  reachability scan failed: %v\n", err)
		}
		return
	}

	// Mark each CVE whose query produced a match.
	reachableCVEs := map[string]bool{}
	for _, m := range res.Transitive {
		entry, ok := byHash[m.Query]
		if !ok {
			continue
		}
		for cve := range entry.cves {
			reachableCVEs[cve] = true
		}
	}
	// Track which CVEs had at least one query that *actually executed* (compiled
	// and ran against ≥1 matching-language source file) so we can mark unreachable
	// confidently. A query that was dropped (unsupported language), had no files
	// of its language in the project, or failed to compile is NOT evidence of
	// non-reachability — its CVE stays unassessed (and is never posted as
	// UNREACHABLE), so the server leaves it under_investigation rather than
	// auto-resolving it to not_affected.
	evaluatedCVEs := map[string]bool{}
	for _, e := range byHash {
		if !res.Executed[reachability.QueryKey(e.query)] {
			continue
		}
		for cve := range e.cves {
			evaluatedCVEs[cve] = true
		}
	}

	for i := range enriched {
		cve := enriched[i].CveID
		if evaluatedCVEs[cve] {
			enriched[i].ReachabilityAssessed = true
		}
		// Collect query hashes for this CVE
		var hashes []string
		for _, e := range byHash {
			if e.cves[cve] {
				hashes = append(hashes, e.query.QueryHash)
			}
		}
		if len(hashes) > 0 {
			enriched[i].ReachabilityQueryHashes = hashes
		}
		switch {
		case reachableCVEs[cve]:
			enriched[i].Reachability = "transitive"
		case evaluatedCVEs[cve]:
			enriched[i].Reachability = "unreachable"
		}
	}

	if verbose {
		fmt.Fprintf(w, "  reachability: %d/%d evaluated CVE(s) reached\n", len(reachableCVEs), len(evaluatedCVEs))
	}
}

// scaJob is one unit of work for the self-healing cli.sca sender. A job either
// carries a slice of PURLs (a discovery/primary request) or a manifest-body
// slot (manifestSlot >= 0). The primary job creates the run/snapshot.
type scaJob struct {
	purls        []string
	primary      bool
	manifestSlot int // index into the body slots, or -1 for none
}

// runSCAJobs drives jobs through send-with-retry and adaptive chunk-size
// reduction. It is the single code path to /v2/cli.sca — there is no legacy
// fallback. Jobs run serially (the primary must succeed before dependent jobs
// can anchor to its snapshot). On a job that still fails after retries:
//   - a multi-PURL job is split in half and both halves are re-queued at the
//     front (the first half inherits the primary flag), so vuln-dense chunks
//     that blow the per-request timeout succeed once small enough;
//   - a single-PURL job that still fails is recorded as unservable (its results
//     are simply omitted — never fetched via a legacy per-PURL loop);
//   - a manifest-only job (no PURLs) that fails is non-fatal and dropped.
//
// buildReq turns a job into the env + request to send (and may signal skip);
// onResult merges each successful response. Returns the unservable PURLs, a
// flag indicating whether any request succeeded, and the first error seen.
func runSCAJobs(
	client *vdb.Client,
	jobs []scaJob,
	buildReq func(job scaJob) (vdb.CliEnv, vdb.CliSCARequest, bool),
	onResult func(job scaJob, resp *vdb.CliResponse[vdb.CliSCAResponse]),
	w io.Writer,
) (unservable []string, anyOK bool, firstErr error) {
	queue := append([]scaJob(nil), jobs...)
	for len(queue) > 0 {
		job := queue[0]
		queue = queue[1:]

		env, req, skip := buildReq(job)
		if skip {
			continue
		}

		label := scaJobLabel(job)
		resp, err := sendCliSCAWithRetry(client, env, req, label, w)
		if err == nil {
			anyOK = true
			onResult(job, resp)
			if verbose {
				fmt.Fprintf(w, "  %s ok\n", label)
			}
			continue
		}
		if firstErr == nil {
			firstErr = err
		}

		switch {
		case len(job.purls) > minChunkSize:
			// Chunk-size reduction: halve and retry the pieces before anything else.
			a, b := splitPurls(job.purls)
			j1 := scaJob{purls: a, primary: job.primary, manifestSlot: -1}
			j2 := scaJob{purls: b, primary: false, manifestSlot: -1}
			queue = append([]scaJob{j1, j2}, queue...)
			if verbose {
				fmt.Fprintf(w, "  %s failed (%v); splitting into %d + %d package(s)\n", label, err, len(a), len(b))
			}
		case len(job.purls) == 1:
			unservable = append(unservable, job.purls...)
			if verbose {
				fmt.Fprintf(w, "  %s unservable after retries (%v)\n", label, err)
			}
		default:
			// Manifest-only job: non-fatal, drop it.
			if verbose {
				fmt.Fprintf(w, "  %s failed (%v); manifest body dropped\n", label, err)
			}
		}
	}
	return unservable, anyOK, firstErr
}

// sendCliSCAWithRetry sends one cli.sca request, retrying transient failures
// (5xx, 429, network/timeout) with exponential backoff + jitter and honouring
// any server Retry-After hint. Terminal errors (400/401/403, decode failures)
// return immediately so we don't burn attempts on unrecoverable conditions.
func sendCliSCAWithRetry(client *vdb.Client, env vdb.CliEnv, req vdb.CliSCARequest, label string, w io.Writer) (*vdb.CliResponse[vdb.CliSCAResponse], error) {
	var lastErr error
	for attempt := 1; attempt <= maxBatchAttempts; attempt++ {
		reqCtx, cancel := context.WithTimeout(context.Background(), cliSCABatchTimeout)
		resp, err := client.CliSCAWithContext(reqCtx, env, req)
		cancel()
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if attempt == maxBatchAttempts || !isRetryableCliErr(err) {
			return nil, err
		}
		delay := backoffDelay(attempt, err)
		if verbose {
			fmt.Fprintf(w, "  %s attempt %d/%d failed (%v); retrying in %s\n", label, attempt, maxBatchAttempts, err, delay.Round(time.Millisecond))
		}
		time.Sleep(delay)
	}
	return nil, lastErr
}

// isRetryableCliErr classifies an error from CliSCAWithContext. Retryable:
// 429, any 5xx, and transport-level failures (timeouts, resets, deadline).
// Terminal: 4xx (auth/bad-request), 404, and response-decode errors.
func isRetryableCliErr(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *vdb.CliAPIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusTooManyRequests || apiErr.StatusCode >= 500
	}
	var nf *vdb.NotFoundError
	if errors.As(err, &nf) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	// Transport-level failures surface as wrapped "failed to execute request"
	// strings; treat those as transient. Decode/marshal failures are terminal.
	return strings.Contains(err.Error(), "failed to execute request")
}

// backoffDelay returns the wait before the next attempt: the server Retry-After
// when present (capped), otherwise capped exponential backoff with light jitter.
func backoffDelay(attempt int, err error) time.Duration {
	var apiErr *vdb.CliAPIError
	if errors.As(err, &apiErr) && apiErr.RetryAfter > 0 {
		return min(apiErr.RetryAfter, scaBackoffMax)
	}
	d := min(scaBackoffBase<<(attempt-1), scaBackoffMax)
	// Deterministic jitter (serial sends, so cross-batch desync isn't needed —
	// this just avoids lock-stepping with server-side windows).
	return d + time.Duration(attempt)*scaBackoffBase/10
}

// splitPurls divides a PURL slice into two roughly equal halves.
func splitPurls(in []string) ([]string, []string) {
	mid := max(len(in)/2, 1)
	return in[:mid], in[mid:]
}

// scaJobLabel renders a short human-readable label for progress output.
func scaJobLabel(job scaJob) string {
	switch {
	case len(job.purls) > 0 && job.primary:
		return fmt.Sprintf("primary batch (%d package(s))", len(job.purls))
	case len(job.purls) > 0:
		return fmt.Sprintf("batch (%d package(s))", len(job.purls))
	default:
		return "manifest body"
	}
}

// chunkPurls splits a slice into batches of at most `size` elements.
func chunkPurls(in []string, size int) [][]string {
	if size <= 0 || len(in) <= size {
		return [][]string{in}
	}
	out := make([][]string, 0, (len(in)+size-1)/size)
	for i := 0; i < len(in); i += size {
		end := i + size
		if end > len(in) {
			end = len(in)
		}
		out = append(out, in[i:end])
	}
	return out
}

// buildCliEnv translates the existing CLI scan context (git, system) into the
// envelope the API expects.
func buildCliEnv(gitCtx *gitctx.GitContext, sysInfo *gitctx.SystemInfo) vdb.CliEnv {
	env := vdb.CliEnv{
		CliVersion: version,
		Commit:     commit,
		BuildDate:  buildDate,
	}
	if sysInfo != nil {
		env.OS = sysInfo.OS
		env.Arch = sysInfo.Arch
		env.Platform = sysInfo.OS
		env.Hostname = sysInfo.Hostname
		env.Shell = sysInfo.Shell
	}
	if gitCtx != nil {
		env.Git = &vdb.CliGitContext{
			Branch:   gitCtx.CurrentBranch,
			Commit:   gitCtx.CurrentCommit,
			Author:   gitCtx.HeadCommitAuthor,
			Remotes:  gitCtx.RemoteURLs,
			Dirty:    gitCtx.IsDirty,
			RepoRoot: gitCtx.RepoRootPath,
		}
	}
	env.ToolMetadata = &vdb.CliSBOMToolMetadata{
		ToolName:    "Vulnetix SCA",
		ToolVersion: version,
		ToolVendor:  "Vulnetix",
		ToolHash:    commit,
	}
	return env
}

// stripManifestContent returns a copy of the manifests with raw bodies removed,
// for the discovery-only chunks that don't trigger persistence.
func stripManifestContent(in []vdb.CliManifestMetadata) []vdb.CliManifestMetadata {
	if len(in) == 0 {
		return nil
	}
	out := make([]vdb.CliManifestMetadata, len(in))
	copy(out, in)
	for i := range out {
		out[i].Content = ""
	}
	return out
}

// scaManifestByteBudget bounds the raw manifest-body bytes carried per /v2/cli.sca
// request, kept well under the server's 8 MiB cap so a repo with large lockfiles
// doesn't overflow a single request.
const scaManifestByteBudget = 3 << 20 // 3 MiB

// packManifestsBySize groups the manifests that carry a raw Content body into
// size-bounded slots (slot s ships on SCA request s+1). A single manifest larger
// than the budget ships alone. Manifests without Content are skipped — their
// metadata rows are created on chunk 0.
func packManifestsBySize(in []vdb.CliManifestMetadata, budget int) [][]vdb.CliManifestMetadata {
	var slots [][]vdb.CliManifestMetadata
	var cur []vdb.CliManifestMetadata
	curBytes := 0
	for _, m := range in {
		if m.Content == "" {
			continue
		}
		sz := len(m.Content)
		if len(cur) > 0 && curBytes+sz > budget {
			slots = append(slots, cur)
			cur, curBytes = nil, 0
		}
		cur = append(cur, m)
		curBytes += sz
	}
	if len(cur) > 0 {
		slots = append(slots, cur)
	}
	return slots
}

// enrichCliEnvForSCA populates the SaaS-persistence-only metadata: repo-level
// licenses, manifest sha256/size, package-manager capabilities. Called only
// from tryCliSCA so the env subcommand stays fast.
func enrichCliEnvForSCA(env *vdb.CliEnv, scanPath string, allPackages []scan.ScopedPackage, gitCtx *gitctx.GitContext) {
	if env == nil {
		return
	}
	repoRoot := scanPath
	if gitCtx != nil && gitCtx.RepoRootPath != "" {
		repoRoot = gitCtx.RepoRootPath
	}
	for _, h := range license.DetectRepoLicense(repoRoot) {
		env.Licenses = append(env.Licenses, vdb.CliLicenseHit{
			SPDXID:      h.SPDXID,
			Name:        h.Name,
			URL:         h.URL,
			Source:      h.Source,
			Acknowledge: h.Acknowledge,
			Text:        h.Text,
		})
	}

	// Manifests: dedupe by absolute path; compute sha256 + size.
	seenManifests := make(map[string]bool)
	for _, pkg := range allPackages {
		manifestPath, ok := resolveScanSourcePath(scanPath, pkg.SourceFile)
		if !ok || seenManifests[manifestPath] {
			continue
		}
		mi, ok := scan.DetectManifest(manifestPath)
		if !ok || mi == nil {
			continue
		}
		seenManifests[manifestPath] = true
		info, err := os.Stat(manifestPath)
		if err != nil {
			continue
		}
		body, rerr := os.ReadFile(manifestPath)
		if rerr != nil {
			continue
		}
		h := sha256.Sum256(body)
		base := filepath.Base(manifestPath)
		ecosystem := mi.Ecosystem
		if ecosystem == "" {
			ecosystem = pkg.Ecosystem
		}
		env.Manifests = append(env.Manifests, vdb.CliManifestMetadata{
			Path:        relativePathFromRoot(repoRoot, manifestPath),
			Ecosystem:   ecosystem,
			IsLock:      mi.IsLock,
			SHA256:      hex.EncodeToString(h[:]),
			Size:        int(info.Size()),
			ContentType: detectManifestContentType(base),
			Registry:    registryForEcosystem(ecosystem),
			Provider:    providerForEcosystem(ecosystem),
			Content:     string(body),
		})
	}

	// PackageManagers list (already populated for env subcommand) — replicate
	// here from the manifest list so the SaaS PackageManagerDetection insert
	// has a row per ecosystem.
	seenEco := make(map[string]bool)
	for _, m := range env.Manifests {
		if m.Ecosystem == "" || seenEco[m.Ecosystem] {
			continue
		}
		seenEco[m.Ecosystem] = true
		env.PackageManagers = append(env.PackageManagers, vdb.CliPackageMgr{
			Ecosystem: m.Ecosystem,
			Manifest:  m.Path,
			IsLock:    m.IsLock,
		})
	}

	// Capabilities: map detected manifest/lockfile basenames → candidate
	// binaries, narrow via lockfiles, and probe each binary for path + version.
	presentFiles := make([]string, 0, len(env.Manifests))
	for _, m := range env.Manifests {
		presentFiles = append(presentFiles, filepath.Base(m.Path))
	}
	for _, rb := range scan.ResolvePackageManagerBinaries(presentFiles) {
		env.Capabilities = append(env.Capabilities, vdb.CliPMCapability{
			Ecosystem:      rb.Ecosystem,
			CapabilityName: "binary:" + rb.Binary,
			Supported:      true,
			Detected:       rb.Detected,
			Confidence:     boolToConfidence(rb.Detected),
			Evidence:       rb.BinaryPath,
			Binary:         rb.Binary,
			BinaryPath:     rb.BinaryPath,
			Version:        rb.Version,
			VersionCommand: rb.VersionCommand,
			Authoritative:  rb.Authoritative,
		})
	}
}

// registryForEcosystem returns the canonical registry base URL for an ecosystem.
func registryForEcosystem(eco string) string {
	switch strings.ToLower(eco) {
	case "npm":
		return "https://registry.npmjs.org"
	case "pypi", "pip", "python":
		return "https://pypi.org"
	case "golang", "go":
		return "https://proxy.golang.org"
	case "cargo", "rust", "crates":
		return "https://crates.io"
	case "rubygems", "gem":
		return "https://rubygems.org"
	case "maven", "java":
		return "https://repo.maven.apache.org"
	case "composer", "packagist", "php":
		return "https://packagist.org"
	case "nuget", ".net":
		return "https://www.nuget.org"
	}
	return ""
}

// providerForEcosystem returns the human-readable registry provider name.
func providerForEcosystem(eco string) string {
	switch strings.ToLower(eco) {
	case "npm":
		return "npm"
	case "pypi", "pip", "python":
		return "PyPI"
	case "golang", "go":
		return "Go Module Proxy"
	case "cargo", "rust", "crates":
		return "crates.io"
	case "rubygems", "gem":
		return "RubyGems"
	case "maven", "java":
		return "Maven Central"
	case "composer", "packagist", "php":
		return "Packagist"
	case "nuget", ".net":
		return "NuGet"
	}
	return ""
}

func boolToConfidence(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.5
}

func detectManifestContentType(basename string) string {
	switch {
	case strings.HasSuffix(basename, ".json"):
		return "application/json"
	case strings.HasSuffix(basename, ".xml"):
		return "application/xml"
	case strings.HasSuffix(basename, ".yaml"), strings.HasSuffix(basename, ".yml"):
		return "application/yaml"
	case strings.HasSuffix(basename, ".toml"):
		return "application/toml"
	}
	return "text/plain"
}

func relativePathFromRoot(root, p string) string {
	if root == "" {
		return p
	}
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return p
	}
	return rel
}

func resolveScanSourcePath(scanRoot, sourceFile string) (string, bool) {
	if sourceFile == "" {
		return "", false
	}
	candidates := []string{}
	if filepath.IsAbs(sourceFile) {
		candidates = append(candidates, sourceFile)
	} else {
		if scanRoot != "" {
			candidates = append(candidates, filepath.Join(scanRoot, sourceFile))
		}
		candidates = append(candidates, sourceFile)
	}
	for _, candidate := range candidates {
		abs, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		if info, err := os.Stat(abs); err == nil && !info.IsDir() {
			return abs, true
		}
	}
	return "", false
}

func boolPtrCLI(b bool) *bool { return &b }

// reportScanFinalization posts the scan's policy-gate decision back to the
// server (POST /v2/cli.finalize), anchored to the IngestionSnapshot UUID, so
// the CliScanEnvironment row records the emitted exit code + per-gate breaches.
// Best-effort: any failure is logged (verbose only) and never changes the
// scan's own exit code. Called on every scan that produced a snapshot, whether
// or not any gate breached.
func reportScanFinalization(snapshotUuid string, breaches []GateBreach, controlFlags []vdb.CliControlFlag, gitCtx *gitctx.GitContext, sysInfo *gitctx.SystemInfo) {
	if snapshotUuid == "" {
		return
	}
	client := newCliClient()
	if client == nil {
		return
	}
	gates := make([]vdb.CliGateResult, 0, len(breaches))
	for _, b := range breaches {
		gates = append(gates, vdb.CliGateResult{Gate: b.Gate, Count: b.Count, Message: b.Message})
	}
	exitCode := 0
	if len(breaches) > 0 {
		exitCode = 1
	}
	env := buildCliEnv(gitCtx, sysInfo)
	resp, err := client.CliFinalize(env, vdb.CliFinalizeRequest{
		IngestionSnapshotUuid: snapshotUuid,
		ExitCode:              exitCode,
		BreakBuild:            len(breaches) > 0,
		Gates:                 gates,
		ControlFlags:          controlFlags,
	})
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "  finalize post failed: %v\n", err)
		}
		return
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "  finalize: persisted=%v (exitCode=%d, gates=%d)\n", resp.Data.Persisted, exitCode, len(gates))
	}
}
