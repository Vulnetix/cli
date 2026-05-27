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
	"fmt"
	"os"
	"time"

	"github.com/vulnetix/cli/v3/internal/cdx"
	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/internal/reachability"
	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

const scaAPIDisabledEnv = "VULNETIX_CLI_SCA_API"

func tryCliSCA(allPackages []scan.ScopedPackage, gitCtx *gitctx.GitContext, sysInfo *gitctx.SystemInfo, scanPath string) (apiServed bool, findings []scan.VulnFinding, enriched []scan.EnrichedVuln) {
	if v := os.Getenv(scaAPIDisabledEnv); v == "off" || v == "0" || v == "false" {
		return false, nil, nil
	}
	if len(allPackages) == 0 {
		return false, nil, nil
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
		return false, nil, nil
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
		return false, nil, nil
	}

	env := buildCliEnv(gitCtx, sysInfo)

	mergedComponents := make([]any, 0, len(uniquePurls))
	mergedVulns := make([]any, 0)
	mergedReach := make([]vdb.CliReachabilityHit, 0)
	tierObserved := ""  // "pro" wins over any spurious community batch
	var anyTierGated bool
	var batchesOK, batchesFailed int
	var firstErr error

	for i, chunk := range chunks {
		resp, err := client.CliSCA(env, vdb.CliSCARequest{
			Purls:   chunk,
			Options: vdb.CliSCAOptions{IncludeReachability: boolPtrCLI(true)},
		})
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
		return false, nil, nil
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
		return false, nil, nil
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

	return true, findings, enriched
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
	return env
}

func boolPtrCLI(b bool) *bool { return &b }
