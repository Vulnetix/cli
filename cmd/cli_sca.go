package cmd

// tryCliSCA encapsulates the /v2/cli.sca round-trip that replaces the
// per-PURL LookupVulns + EnrichVulns fan-out. Returns:
//   - apiServed=true  → caller uses findings/enriched as-is, skips legacy
//   - apiServed=false → caller falls back to the legacy two-loop path
//
// Failures are non-fatal — a one-line note goes to stderr, but the scan
// continues via the legacy path so a flaky network or expired credential
// never breaks `vulnetix sca`.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

const scaAPIDisabledEnv = "VULNETIX_CLI_SCA_API"

// cliSCAGateOptions tells tryCliSCA which per-package gate signals the active
// scan flags need, so the cli.sca round-trip requests them (and only them).
type cliSCAGateOptions struct {
	Cooldown   bool // --cooldown
	VersionLag bool // --version-lag
	EOL        bool // --block-eol (package-level)
	Malware    bool // --block-malware
}

func tryCliSCA(allPackages []scan.ScopedPackage, manifestGroups []scan.ManifestGroup, licenseByKey map[string]string, gitCtx *gitctx.GitContext, sysInfo *gitctx.SystemInfo, scanPath string, gateOpts cliSCAGateOptions) (apiServed bool, findings []scan.VulnFinding, enriched []scan.EnrichedVuln, insights []vdb.CliPackageInsight, snapshotUuid string, snapshotURL string) {
	if v := os.Getenv(scaAPIDisabledEnv); v == "off" || v == "0" || v == "false" {
		return false, nil, nil, nil, "", ""
	}
	if len(allPackages) == 0 {
		return false, nil, nil, nil, "", ""
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
		return false, nil, nil, nil, "", ""
	}

	// Chunk PURLs to stay well inside CloudFront's 60s origin timeout.
	// Smaller chunks trade a few extra round-trips for predictable latency
	// against vuln-dense fixtures where each PURL may fan out to dozens of
	// CVE rows in the handler.
	const sCAChunkSize = 25
	chunks := chunkPurls(uniquePurls, sCAChunkSize)

	// One default-visible status line; per-batch progress is verbose-only.
	if !silent {
		fmt.Fprintf(os.Stderr, "Querying VDB via /v2/cli.sca: %d unique package(s) in %d batch(es)...\n", len(uniquePurls), len(chunks))
	}

	client := newCliClient() // /v2 client with 180s timeout for fan-out lookups
	if client == nil {
		return false, nil, nil, nil, "", ""
	}

	env := buildCliEnv(gitCtx, sysInfo)
	enrichCliEnvForSCA(&env, scanPath, allPackages, gitCtx)

	// The heavy env (raw manifest bodies) rides only on chunk 0 — the chunk that
	// carries Packages and triggers server-side persistence. Subsequent chunks
	// are discovery-only, so we strip the manifest bodies to stay within the
	// request size cap.
	lightEnv := env
	lightEnv.Manifests = stripManifestContent(env.Manifests)

	// Per-PURL Packages list with manifest + chain info. Sent on the first
	// chunk only so the server creates exactly one IngestionSnapshot for the
	// whole scan (subsequent chunks set Packages=nil and are discovery-only).
	allCliPackages := buildCliPackages(allPackages, manifestGroups, licenseByKey)

	mergedComponents := make([]any, 0, len(uniquePurls))
	mergedVulns := make([]any, 0)
	mergedReach := make([]vdb.CliReachabilityHit, 0)
	mergedInsights := make([]vdb.CliPackageInsight, 0)
	tierObserved := "" // "pro" wins over any spurious community batch
	var anyTierGated bool
	var batchesOK, batchesFailed int
	var firstErr error
	var snapshot *vdb.CliIngestionSnapshot
	var persistedFindings []vdb.CliFindingResult

	for i, chunk := range chunks {
		req := vdb.CliSCARequest{
			Purls: chunk,
			Options: vdb.CliSCAOptions{
				IncludeReachability: boolPtrCLI(true),
				IncludeCooldown:     gateOpts.Cooldown,
				IncludeVersionLag:   gateOpts.VersionLag,
				IncludeEOL:          gateOpts.EOL,
				IncludeMalware:      gateOpts.Malware,
			},
		}
		reqEnv := lightEnv
		if i == 0 {
			// Chunk 0 carries the heavy env (manifest bodies) + the full package
			// list, and creates the run/snapshot.
			req.Packages = allCliPackages
			reqEnv = env
		} else if snapshot != nil {
			// Discovery chunks append their findings under chunk-0's run. Send the
			// lightweight package list (no manifest bodies) so each chunk's findings
			// get package context; only when chunk 0 actually persisted (snapshot set),
			// so we never create duplicate runs.
			req.Packages = allCliPackages
			req.IngestionSnapshotUuid = snapshot.Uuid
		}
		resp, err := client.CliSCA(reqEnv, req)
		if err != nil {
			batchesFailed++
			if firstErr == nil {
				firstErr = err
			}
			if verbose {
				fmt.Fprintf(os.Stderr, "  batch %d/%d failed (%v), continuing\n", i+1, len(chunks), err)
			}
			continue
		}
		batchesOK++
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
		// Capture the snapshot once (chunk 0 creates it). Findings now come back
		// from every chunk (chunk 0 + appended discovery chunks); accumulate all
		// of them so reachability can correlate findings across the whole scan.
		if snapshot == nil && resp.Data.IngestionSnapshot != nil {
			snapshot = resp.Data.IngestionSnapshot
		}
		persistedFindings = append(persistedFindings, resp.Data.Findings...)
		if verbose {
			fmt.Fprintf(os.Stderr, "  batch %d/%d: %d component(s), %d vuln(s), %d reachability query(ies)\n", i+1, len(chunks), len(mergedComponents), len(mergedVulns), len(mergedReach))
		}
	}

	// Only fall back when *every* batch failed. Partial success is still a win
	// over the legacy per-PURL loop.
	if batchesOK == 0 {
		if !silent {
			fmt.Fprintf(os.Stderr, "  /v2/cli.sca all %d batch(es) failed (%v), falling back to legacy lookup\n", len(chunks), firstErr)
		}
		return false, nil, nil, nil, "", ""
	}
	if batchesFailed > 0 && !silent {
		fmt.Fprintf(os.Stderr, "  /v2/cli.sca completed with %d/%d batch(es) ok, %d failed\n", batchesOK, len(chunks), batchesFailed)
	}

	// Only show the upgrade note when we *consistently* observed community
	// across every batch. A single Pro response is enough to suppress it —
	// guards against transient replica/cache flaps on the server.
	if anyTierGated && tierObserved != "pro" && !silent {
		fmt.Fprintln(os.Stderr, "Note: reachability requires Pro / Team / Business / Enterprise — upgrade at https://www.vulnetix.com/pricing")
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
			fmt.Fprintln(os.Stderr, "  /v2/cli.sca returned no CycloneDX document, falling back to legacy lookup")
		}
		return false, nil, nil, nil, "", ""
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "  /v2/cli.sca returned %d finding(s) across %d package(s)\n", len(findings), len(uniquePurls))
	}

	// Pro+ tiers: run the returned tree-sitter queries locally so the
	// Reachability column on each finding reflects actual code analysis,
	// not just whether the server delivered queries. Community gets nothing
	// here because the server already returned reachability=nil.
	if len(mergedReach) > 0 {
		runReachabilityForFindings(mergedReach, enriched, scanPath)
	}

	// Symbol fallback (all tiers): for any finding the tree-sitter pass
	// didn't verdict, grep local source for affectedRoutines/Files/Modules.
	runSymbolFallback(enriched, scanPath)

	// Post reachability evidence back to the server when persistence
	// succeeded. Best-effort: a failure here doesn't break the local scan.
	if snapshot != nil {
		postReachabilityToSnapshot(client, env, snapshot, persistedFindings, enriched, gitCtx)
		if !silent {
			fmt.Fprintf(os.Stderr, "Snapshot: %s\n", snapshot.URL)
		}
	}

	finalSnapshotUuid := ""
	finalSnapshotURL := ""
	if snapshot != nil {
		finalSnapshotUuid = snapshot.Uuid
		finalSnapshotURL = snapshot.URL
	}
	return true, findings, enriched, mergedInsights, finalSnapshotUuid, finalSnapshotURL
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
		out = append(out, vdb.CliPackageEntry{
			Purl:          purl,
			Name:          p.Name,
			Version:       p.Version,
			Ecosystem:     p.Ecosystem,
			ManifestFile:  p.SourceFile,
			Scope:         scope,
			License:       licenseByKey[key],
			IntroducedVia: [][]string{chain},
		})
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

func postReachabilityToSnapshot(client *vdb.Client, env vdb.CliEnv, snapshot *vdb.CliIngestionSnapshot, persisted []vdb.CliFindingResult, enriched []scan.EnrichedVuln, gitCtx *gitctx.GitContext) {
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
			fmt.Fprintf(os.Stderr, "  reachability post failed: %v\n", err)
		}
		return
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "  reachability persisted: %d (sbom=%s, vex=%s)\n", resp.Data.Persisted, resp.Data.SBOMUrl, resp.Data.VEXUrl)
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
func runSymbolFallback(enriched []scan.EnrichedVuln, projectRoot string) {
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
		fmt.Fprintf(os.Stderr, "  running symbol fallback for %d CVE(s) in %s...\n", len(inputs), cwd)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := reachability.MatchAffectedSymbols(ctx, reachability.SymbolMatchRequest{
		ProjectRoot: cwd,
		Inputs:      inputs,
	})
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "  symbol fallback failed: %v\n", err)
		}
		return
	}
	if res == nil || len(res.HitsByCVE) == 0 {
		if verbose {
			fmt.Fprintln(os.Stderr, "  symbol fallback: no hits")
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
		fmt.Fprintf(os.Stderr, "  semantic reachability: %d CVE(s) matched in source\n", len(res.HitsByCVE))
	}
}

// runReachabilityForFindings turns the per-CVE tree-sitter queries returned
// by /v2/cli.sca into actual reachability results by running them across the
// project root. CVEs whose queries match → Reachability="transitive"; CVEs
// whose queries run cleanly with zero matches → "unreachable"; CVEs we
// couldn't evaluate stay empty. Direct-mode (per-install-directory) requires
// ScopedPackage routing and lands in a follow-up.
func runReachabilityForFindings(hits []vdb.CliReachabilityHit, enriched []scan.EnrichedVuln, projectRoot string) {
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
		fmt.Fprintf(os.Stderr, "  running %d reachability query(ies) across %s...\n", len(queries), cwd)
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
			fmt.Fprintf(os.Stderr, "  reachability scan failed: %v\n", err)
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
	// Track which CVEs had at least one query run for them so we can mark
	// unreachable confidently (vs "no queries returned, can't say").
	evaluatedCVEs := map[string]bool{}
	for _, e := range byHash {
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
		fmt.Fprintf(os.Stderr, "  reachability: %d/%d evaluated CVE(s) reached\n", len(reachableCVEs), len(evaluatedCVEs))
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
