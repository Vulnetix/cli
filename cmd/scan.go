package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/internal/auth"
	"github.com/vulnetix/cli/internal/cache"
	"github.com/vulnetix/cli/internal/cdx"
	"github.com/vulnetix/cli/internal/display"
	"github.com/vulnetix/cli/internal/gitctx"
	"github.com/vulnetix/cli/internal/memory"
	"github.com/vulnetix/cli/internal/scan"
	"github.com/vulnetix/cli/internal/tty"
	"github.com/vulnetix/cli/internal/tui"
	"github.com/vulnetix/cli/internal/vdb"
)

// SeverityBreachError is returned when --severity threshold is breached.
// It signals main() to exit with code 1 without printing a redundant error message.
type SeverityBreachError struct {
	threshold string
	count     int
}

func (e *SeverityBreachError) Error() string {
	return fmt.Sprintf("severity threshold %q breached: %d %s",
		e.threshold, e.count, pluralise("vulnerability", e.count))
}

// scanCmd is the top-level scan command — discovers manifests, parses them locally,
// queries the VDB for vulnerabilities, writes a CycloneDX BOM and memory.yaml,
// then outputs either a pretty summary or CycloneDX JSON.
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan local manifests for vulnerabilities (local analysis, no upload)",
	Long: `Scan local manifest files for vulnerabilities using the Vulnetix VDB API.

Manifests are discovered by walking the directory tree, parsed locally on your
machine, and each package is looked up against the VDB vulnerability database.
No file contents are ever uploaded to any server.

Results are organised by the native scope of each package manager:
  npm           production, development, peer, optional
  Python        production, development  (Pipfile / pyproject.toml) / production  (requirements.txt, uv.lock)
  Go            production  (no scope distinction in go.mod / go.sum)
  Rust          production  (no scope distinction in Cargo.lock)
  Ruby          production  (group info requires Gemfile)
  Maven         production, test, provided, runtime, system
  Composer      production, development
  Yarn / pnpm   production  (scope requires correlation with package.json)

After scanning:
  • A CycloneDX SBOM (default 1.7, supports 1.2-1.7) is written to .vulnetix/sbom.cdx.json
  • Scan state is recorded in           .vulnetix/memory.yaml
  • A summary or BOM JSON is printed to stdout

Examples:
  vulnetix scan                        # pretty output, auto-discover manifests
  vulnetix scan --path ./myproject
  vulnetix scan --depth 5
  vulnetix scan --exclude "test*"
  vulnetix scan -f cdx17               # emit CycloneDX 1.7 JSON to stdout
  vulnetix scan -f cdx16               # emit CycloneDX 1.6 JSON to stdout
  vulnetix scan -f cdx15               # emit CycloneDX 1.5 JSON to stdout
  vulnetix scan -f cdx14               # emit CycloneDX 1.4 JSON to stdout
  vulnetix scan -f cdx13               # emit CycloneDX 1.3 JSON to stdout
  vulnetix scan -f cdx12               # emit CycloneDX 1.2 JSON to stdout
  vulnetix scan -f json                # emit raw JSON findings to stdout
  vulnetix scan --no-progress          # suppress progress bar
  vulnetix scan --severity high        # exit 1 if any vuln is high or critical
  vulnetix scan --severity low         # exit 1 on any scored severity (low+)
  vulnetix scan --severity critical -f cdx17  # CDX output + break on critical
  vulnetix scan --from-memory                  # reconstruct pretty output from .vulnetix/sbom.cdx.json
  vulnetix scan --from-memory --fresh-exploits # reconstruct + fetch latest exploit intel
  vulnetix scan --from-memory --fresh-advisories # reconstruct + fetch latest remediation plans
  vulnetix scan --from-memory --fresh-vulns    # reconstruct + re-check affected versions
  vulnetix scan --dry-run                      # detect files + parse packages, then show memory — zero API calls
  vulnetix scan --dry-run --path ./myproject   # dry run on a specific directory`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		initDisplayContext(cmd, display.ModeText)
		// Credentials are optional — community fallback is used when absent.
		return resolveVDBCredentials(false)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// ── --dry-run path ──────────────────────────────────────────────────
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		if dryRun {
			for _, freshFlag := range []string{"fresh-exploits", "fresh-advisories", "fresh-vulns"} {
				if v, _ := cmd.Flags().GetBool(freshFlag); v {
					return fmt.Errorf("--%s cannot be used with --dry-run (dry run makes no API calls)", freshFlag)
				}
			}
			scanPath, _ := cmd.Flags().GetString("path")
			depth, _ := cmd.Flags().GetInt("depth")
			excludes, _ := cmd.Flags().GetStringArray("exclude")
			showPaths, _ := cmd.Flags().GetBool("paths")
			noExploits, _ := cmd.Flags().GetBool("no-exploits")
			noRemediation, _ := cmd.Flags().GetBool("no-remediation")
			severityThreshold, _ := cmd.Flags().GetString("severity")
			if scanPath == "" {
				scanPath = "."
			}
			if abs, err := filepath.Abs(scanPath); err == nil {
				scanPath = abs
			}
			return runDryScan(scanPath, depth, excludes, showPaths, noExploits, noRemediation, severityThreshold)
		}

		// ── --from-memory path ────────────────────────────────────────────
		fromMemory, _ := cmd.Flags().GetBool("from-memory")
		if fromMemory {
			freshExploits, _ := cmd.Flags().GetBool("fresh-exploits")
			freshAdvisories, _ := cmd.Flags().GetBool("fresh-advisories")
			freshVulns, _ := cmd.Flags().GetBool("fresh-vulns")
			return LoadFromMemory(".", freshExploits, freshAdvisories, freshVulns)
		}

		// Validate that --fresh-* flags require --from-memory.
		if freshExploits, _ := cmd.Flags().GetBool("fresh-exploits"); freshExploits {
			return fmt.Errorf("--fresh-exploits requires --from-memory")
		}
		if freshAdvisories, _ := cmd.Flags().GetBool("fresh-advisories"); freshAdvisories {
			return fmt.Errorf("--fresh-advisories requires --from-memory")
		}
		if freshVulns, _ := cmd.Flags().GetBool("fresh-vulns"); freshVulns {
			return fmt.Errorf("--fresh-vulns requires --from-memory")
		}

		scanPath, _ := cmd.Flags().GetString("path")
		depth, _ := cmd.Flags().GetInt("depth")
		excludes, _ := cmd.Flags().GetStringArray("exclude")
		outputFmt, _ := cmd.Flags().GetString("format")
		concurrency, _ := cmd.Flags().GetInt("concurrency")
		noProgress, _ := cmd.Flags().GetBool("no-progress")
		showPaths, _ := cmd.Flags().GetBool("paths")
		noExploits, _ := cmd.Flags().GetBool("no-exploits")
		noRemediation, _ := cmd.Flags().GetBool("no-remediation")
		severityThreshold, _ := cmd.Flags().GetString("severity")

		// Normalise and validate the severity threshold.
		if severityThreshold != "" {
			severityThreshold = strings.ToLower(strings.TrimSpace(severityThreshold))
			valid := false
			for _, v := range scan.ValidSeverityThresholds {
				if severityThreshold == v {
					valid = true
					break
				}
			}
			if !valid {
				return fmt.Errorf("invalid --severity %q: must be one of: %s",
					severityThreshold, strings.Join(scan.ValidSeverityThresholds, ", "))
			}
		}

		if scanPath == "" {
			scanPath = "."
		}
		if abs, err := filepath.Abs(scanPath); err == nil {
			scanPath = abs
		}

		// ── 1. Collect git context early for display ───────────────────────
		gitCtx := gitctx.Collect(scanPath)

		fmt.Fprintf(os.Stderr, "Scanning %s (depth: %d)...\n", scanPath, depth)
		if gitCtx != nil {
			commitShort := gitCtx.CurrentCommit
			if len(commitShort) > 8 {
				commitShort = commitShort[:8]
			}
			remote := ""
			if len(gitCtx.RemoteURLs) > 0 {
				remote = gitCtx.RemoteURLs[0]
			}
			fmt.Fprintf(os.Stderr, "Git: %s @ %s (%s)\n", gitCtx.CurrentBranch, commitShort, remote)
		}
		fmt.Fprintln(os.Stderr)

		// ── 2. Discover files ──────────────────────────────────────────────
		files, err := scan.WalkForScanFiles(scan.WalkOptions{
			RootPath: scanPath,
			MaxDepth: depth,
			Excludes: excludes,
		})
		if err != nil {
			return fmt.Errorf("failed to scan directory: %w", err)
		}
		if len(files) == 0 {
			fmt.Fprintln(os.Stderr, "No scannable files detected.")
			return nil
		}

		// ── 3. Display detected files ──────────────────────────────────────
		fmt.Fprintln(os.Stderr, "Detected files:")
		t := display.NewTerminal()
		var seedBOM *cdx.BOM
		var vulnetixSeedBOM *cdx.BOM
		var supportedFiles []scan.DetectedFile
		for _, f := range files {
			switch f.FileType {
			case scan.FileTypeManifest:
				lockStr := ""
				if f.ManifestInfo.IsLock {
					lockStr = "lock"
				}
				supportedStr := ""
				if !f.Supported {
					supportedStr = " [not supported]"
				}
				fmt.Fprintf(os.Stderr, "  %-40s manifest    %-10s (%s) %s%s\n",
					f.RelPath, f.ManifestInfo.Ecosystem, f.ManifestInfo.Language, lockStr, supportedStr)
			case scan.FileTypeSPDX:
				fmt.Fprintf(os.Stderr, "  %-40s spdx        v%-9s\n", f.RelPath, f.SBOMVersion)
			case scan.FileTypeCycloneDX:
				// Parse the CDX to check the producer.
				cdxBom, cdxErr := parseCDXForScan(f.Path)
				if cdxErr == nil && isVulnetixSCA(cdxBom) {
					fmt.Fprintf(os.Stderr, "  %-40s %s\n", f.RelPath,
						display.Teal(t, "[skipped — produced by vulnetix-sca]"))
					if vulnetixSCAVersion(cdxBom) == version {
						vulnetixSeedBOM = cdxBom
					}
					continue
				}
				if cdxErr == nil && cdxBom != nil {
					fmt.Fprintf(os.Stderr, "  %-40s cyclonedx   v%-8s (%d comp, %d vulns)\n",
						f.RelPath, f.SBOMVersion, len(cdxBom.Components), len(cdxBom.Vulnerabilities))
					if len(cdxBom.Components) > 0 || len(cdxBom.Vulnerabilities) > 0 {
						seedBOM = cdxBom
					}
					if len(cdxBom.Components) > 0 {
						f.Supported = true
						supportedFiles = append(supportedFiles, f)
					}
				} else {
					fmt.Fprintf(os.Stderr, "  %-40s cyclonedx   v%-9s\n", f.RelPath, f.SBOMVersion)
				}
			}
			if f.Supported && f.FileType == scan.FileTypeManifest {
				supportedFiles = append(supportedFiles, f)
			}
		}

		if len(supportedFiles) == 0 {
			fmt.Fprintln(os.Stderr, "\nNo supported manifest files found for scanning.")
			return nil
		}

		// ── 4. Collect host environment ─────────────────────────────────────
		sysInfo := gitctx.CollectSystemInfo()

		// ── 5. Run local scan ──────────────────────────────────────────────
		return runLocalScan(
			cmd.Context(),
			supportedFiles,
			scanPath,
			outputFmt,
			concurrency,
			noProgress,
			showPaths,
			noExploits,
			noRemediation,
			severityThreshold,
			seedBOM,
			vulnetixSeedBOM,
			gitCtx,
			sysInfo,
		)
	},
}

// scanStatusCmd is kept for backward compatibility — checks status of a previously
// submitted (legacy) remote scan.
var scanStatusCmd = &cobra.Command{
	Use:   "status <scan-id>",
	Short: "Check the status of a previously submitted remote scan",
	Long: `Check the status of a scan submitted to the VDB API (legacy remote scan mode).

Examples:
  vulnetix scan status abc123
  vulnetix scan status abc123 --poll`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		scanID := args[0]
		poll, _ := cmd.Flags().GetBool("poll")
		pollInterval, _ := cmd.Flags().GetInt("poll-interval")
		output, _ := cmd.Flags().GetString("output")

		vdbAPIVersion = "v2"
		client := newVDBClient()

		if poll {
			return pollScanResultsLegacy(client, []string{scanID}, pollInterval, output)
		}

		result, err := client.V2ScanStatus(scanID)
		if err != nil {
			return fmt.Errorf("failed to get scan status: %w", err)
		}
		printRateLimit(client)
		return printOutput(result, output)
	},
}

// ---------------------------------------------------------------------------
// Local scan engine
// ---------------------------------------------------------------------------

// runLocalScan is the core of the new scan flow:
//  1. Parse each manifest file locally → []ScopedPackage
//  2. Query VDB SearchPackages for each unique (name, ecosystem) pair
//  3. Build scan results organised by scope
//  4. Write CycloneDX BOM to .vulnetix/sbom.cdx.json
//  5. Update .vulnetix/memory.yaml
//  6. Output pretty summary or CDX JSON to stdout
//
// When --severity is set and any enriched vulnerability's MaxSeverity meets or
// exceeds the threshold the function returns a non-nil error that causes the
// process to exit with code 1.
func runLocalScan(
	ctx context.Context,
	files []scan.DetectedFile,
	rootPath string,
	outputFmt string,
	concurrency int,
	noProgress bool,
	showPaths bool,
	noExploits bool,
	noRemediation bool,
	severityThreshold string,
	seedBOM *cdx.BOM,
	vulnetixSeedBOM *cdx.BOM,
	gitCtx *gitctx.GitContext,
	sysInfo *gitctx.SystemInfo,
) error {
	// Create a v1 VDB client for package search (not the upload/scan v2 client).
	client := newSearchClient()

	fmt.Fprintf(os.Stderr, "\nAnalysing %d file(s)... parsing manifests locally.\n\n", len(files))

	// ── Parse manifests ────────────────────────────────────────────────────
	var localResults []cdx.LocalScanResult
	allPackages := make([]scan.ScopedPackage, 0, 256)

	for _, f := range files {
		// CDX input files: extract components as packages.
		if f.FileType == scan.FileTypeCycloneDX {
			cdxBom, err := parseCDXForScan(f.Path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  %-40s parse error: %v\n", f.RelPath, err)
				continue
			}
			pkgs := buildPackagesFromCDX(cdxBom.Components, f.RelPath)
			scopeCounts := map[string]int{}
			for _, p := range pkgs {
				scopeCounts[p.Scope]++
			}
			fmt.Fprintf(os.Stderr, "  %-40s %d packages%s\n", f.RelPath, len(pkgs), formatScopeCounts(scopeCounts))
			localResults = append(localResults, cdx.LocalScanResult{File: f, Packages: pkgs})
			allPackages = append(allPackages, pkgs...)
			continue
		}
		if f.ManifestInfo == nil {
			continue
		}
		pkgs, err := scan.ParseManifestWithScope(f.Path, f.ManifestInfo.Type)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %-40s parse error: %v\n", f.RelPath, err)
			continue
		}

		// Replace absolute path with relative path in each package.
		for i := range pkgs {
			pkgs[i].SourceFile = f.RelPath
		}

		// Count by scope for the per-file summary line.
		scopeCounts := map[string]int{}
		for _, p := range pkgs {
			scopeCounts[p.Scope]++
		}
		scopeSummary := formatScopeCounts(scopeCounts)
		fmt.Fprintf(os.Stderr, "  %-40s %d packages%s\n", f.RelPath, len(pkgs), scopeSummary)

		localResults = append(localResults, cdx.LocalScanResult{File: f, Packages: pkgs})
		allPackages = append(allPackages, pkgs...)
	}

	if len(allPackages) == 0 {
		fmt.Fprintln(os.Stderr, "\nNo packages found to analyse.")
		return nil
	}

	// ── Count unique packages to query ───────────────────────────────────
	uniqueCount := countUniquePackages(allPackages)
	fmt.Fprintf(os.Stderr, "\nQuerying VDB for %d unique package(s)...\n", uniqueCount)

	// ── Query VDB ──────────────────────────────────────────────────────────
	isInteractive := tty.IsInteractive() && !noProgress
	var progressFn func(done, total int)

	if isInteractive {
		progressFn = func(done, total int) {
			pct := 0
			if total > 0 {
				pct = done * 100 / total
			}
			bar := renderProgressBar(done, total, 30)
			fmt.Fprintf(os.Stderr, "\r  %s %d/%d (%d%%) ", bar, done, total, pct)
		}
	} else if !noProgress {
		// Non-interactive: print dot per 10 packages
		progressFn = func(done, total int) {
			if done%10 == 0 || done == total {
				fmt.Fprintf(os.Stderr, "\r  %d/%d", done, total)
			}
		}
	}

	queryCtx := ctx
	if queryCtx == nil {
		queryCtx = context.Background()
	}

	allVulns, lookupStats, lookupErr := scan.LookupVulns(queryCtx, client, allPackages, concurrency, progressFn)
	if progressFn != nil {
		fmt.Fprintln(os.Stderr) // newline after progress
	}

	// ── Lookup summary ────────────────────────────────────────────────────
	hasPartial := lookupErr != nil && len(allVulns) > 0
	printLookupSummary(client, lookupStats, lookupErr, hasPartial)

	if lookupErr != nil && len(allVulns) == 0 {
		return fmt.Errorf("VDB lookup failed: %w", lookupErr)
	}

	// Attach vulns to each file result.
	for i := range localResults {
		for _, v := range allVulns {
			if v.SourceFile == localResults[i].File.RelPath {
				localResults[i].Vulns = append(localResults[i].Vulns, v)
			}
		}
	}
	// ── Enrich: version filter, exploits, remediation ────────────────────
	v2Client := newEnrichmentClient()

	enrichCount := len(allVulns)
	if enrichCount > 0 {
		fmt.Fprintf(os.Stderr, "\nEnriching %s (version check, exploits, remediation)...\n",
			pluralise("vulnerability", enrichCount))
	}

	var enrichProgressFn func(done, total int)
	if isInteractive && enrichCount > 0 {
		enrichProgressFn = func(done, total int) {
			pct := 0
			if total > 0 {
				pct = done * 100 / total
			}
			bar := renderProgressBar(done, total, 30)
			fmt.Fprintf(os.Stderr, "\r  %s %d/%d (%d%%) ", bar, done, total, pct)
		}
	}

	enrichedVulns, err := scan.EnrichVulns(queryCtx, client, v2Client, allVulns, allPackages, concurrency, enrichProgressFn)
	if enrichProgressFn != nil {
		fmt.Fprintln(os.Stderr)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "  warning: enrichment failed: %v\n", err)
	}

	// Attach enriched vulns back to their file results so the BOM gets full ratings.
	enrichedByKey := make(map[string]scan.EnrichedVuln, len(enrichedVulns))
	for _, ev := range enrichedVulns {
		enrichedByKey[ev.CveID+"::"+ev.PackageName] = ev
	}
	for i := range localResults {
		for _, v := range localResults[i].Vulns {
			if ev, ok := enrichedByKey[v.CveID+"::"+v.PackageName]; ok {
				localResults[i].EnrichedVulns = append(localResults[i].EnrichedVulns, ev)
			}
		}
		// Deduplicate EnrichedVulns within each file result.
		seen := make(map[string]bool)
		deduped := localResults[i].EnrichedVulns[:0]
		for _, ev := range localResults[i].EnrichedVulns {
			k := ev.CveID + "::" + ev.PackageName
			if !seen[k] {
				seen[k] = true
				deduped = append(deduped, ev)
			}
		}
		localResults[i].EnrichedVulns = deduped
	}

	// Build manifest groups for dep graph display.
	filePackages := map[string][]scan.ScopedPackage{}
	fileEcosystems := map[string]string{}
	for _, r := range localResults {
		filePackages[r.File.RelPath] = r.Packages
		if r.File.ManifestInfo != nil {
			fileEcosystems[r.File.RelPath] = r.File.ManifestInfo.Ecosystem
		}
	}
	manifestGroups := scan.BuildManifestGroups(filePackages, fileEcosystems)

	// Populate full dependency graph edges when --paths is requested.
	if showPaths {
		for i := range manifestGroups {
			mg := &manifestGroups[i]
			if mg.Graph != nil && mg.Ecosystem == "golang" {
				graphDir := filepath.Join(rootPath, mg.Dir)
				if err := mg.Graph.PopulateGoModGraph(graphDir); err != nil {
					fmt.Fprintf(os.Stderr, "  warning: go mod graph failed in %s: %v\n", mg.Dir, err)
				}
			}
		}
	}

	// Collect IDS rules.
	idsRules := scan.CollectIDSRules(enrichedVulns)

	// ── Write .vulnetix/sbom.cdx.json ────────────────────────────────────
	vulnetixDir := filepath.Join(rootPath, ".vulnetix")
	sbomPath := filepath.Join(vulnetixDir, "sbom.cdx.json")
	scanCtx := &cdx.ScanContext{
		Git:         gitCtx,
		System:      sysInfo,
		ToolVersion: version,
	}
	// Prefer vulnetix-sca seed (version-matched) over external CDX seed.
	effectiveSeed := seedBOM
	if vulnetixSeedBOM != nil {
		effectiveSeed = vulnetixSeedBOM
	}
	bom := cdx.BuildFromLocalScan(localResults, "1.7", scanCtx, effectiveSeed)
	if err := writeBOMToFile(bom, sbomPath); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: could not write BOM: %v\n", err)
	}

	// ── Write IDS rules if any ───────────────────────────────────────────
	rulesPath := ""
	if len(idsRules) > 0 {
		rulesPath = filepath.Join(vulnetixDir, "detection-rules.rules")
		if err := writeIDSRulesFile(rulesPath, idsRules); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: could not write IDS rules: %v\n", err)
			rulesPath = ""
		}
	}

	// ── Update .vulnetix/memory.yaml ──────────────────────────────────────
	mem, _ := memory.Load(vulnetixDir)
	if mem == nil {
		mem = &memory.Memory{Version: "1"}
	}
	rec := buildScanRecord(localResults, allVulns, files, rootPath, gitCtx, sysInfo, sbomPath)
	if rulesPath != "" {
		rec.IDSRulesPath = ".vulnetix/detection-rules.rules"
		rec.IDSRulesCount = len(idsRules)
	}
	mem.RecordScan(rec)
	if err := memory.Save(vulnetixDir, mem); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: could not update memory.yaml: %v\n", err)
	}

	// ── Output ────────────────────────────────────────────────────────────
	specVersion, isRaw := cdx.NormalizeFormat(outputFmt)

	// ── Severity threshold check ───────────────────────────────────────────
	// Evaluated after writing artefacts so that the SBOM and memory.yaml are
	// always written regardless of exit code, giving CI pipelines access to
	// the full findings even when the build is broken.
	var severityBreak bool
	var severityBreakVulns []scan.EnrichedVuln
	if severityThreshold != "" {
		for _, ev := range enrichedVulns {
			if scan.SeverityMeetsThreshold(ev.MaxSeverity, severityThreshold) {
				severityBreak = true
				severityBreakVulns = append(severityBreakVulns, ev)
			}
		}
	}

	// If no format is specified and we are in a terminal, print a pretty summary.
	if outputFmt == "" && isInteractive {
		printPrettyScanSummary(enrichedVulns, manifestGroups, allPackages, showPaths, noExploits, noRemediation, sbomPath, vulnetixDir, rulesPath, severityThreshold)
		if severityBreak {
			fmt.Fprintln(os.Stderr)
			fmt.Fprintf(os.Stderr, "  ✗ Severity threshold breached: --%s %s triggered by %d %s\n",
				"severity", severityThreshold, len(severityBreakVulns),
				pluralise("vulnerability", len(severityBreakVulns)))
			return &SeverityBreachError{threshold: severityThreshold, count: len(severityBreakVulns)}
		}
		return nil
	}

	// Otherwise emit to stdout in the requested machine-readable format.
	if isRaw {
		if severityBreak {
			_ = writeRawLocalJSON(localResults)
			return &SeverityBreachError{threshold: severityThreshold, count: len(severityBreakVulns)}
		}
		return writeRawLocalJSON(localResults)
	}
	// Re-build with the requested spec version for stdout.
	outBOM := cdx.BuildFromLocalScan(localResults, specVersion, scanCtx, seedBOM)
	if err := outBOM.WriteJSON(os.Stdout); err != nil {
		return err
	}
	if severityBreak {
		return &SeverityBreachError{threshold: severityThreshold, count: len(severityBreakVulns)}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Dry-run
// ---------------------------------------------------------------------------

// runDryScan performs the full local detection and parsing pipeline without
// making any network (API) calls. After detection it checks for existing scan
// memory (.vulnetix/sbom.cdx.json) and renders it exactly as --from-memory
// would, but still without any API calls.
func runDryScan(
	scanPath string,
	depth int,
	excludes []string,
	_ bool, // showPaths — reserved; dep graph requires go mod graph (network)
	_ bool, // noExploits
	_ bool, // noRemediation
	severityThreshold string,
) error {
	t := display.NewTerminal()

	// ── Header ────────────────────────────────────────────────────────────
	fmt.Fprintln(os.Stderr, display.Bold(t, "[DRY RUN]"),
		display.Muted(t, "— no API calls will be made"))
	fmt.Fprintln(os.Stderr)

	// ── 1. Collect git context ────────────────────────────────────────────
	gitCtx := gitctx.Collect(scanPath)

	fmt.Fprintf(os.Stderr, "Scanning %s (depth: %d)...\n", scanPath, depth)
	if gitCtx != nil {
		commitShort := gitCtx.CurrentCommit
		if len(commitShort) > 8 {
			commitShort = commitShort[:8]
		}
		remote := ""
		if len(gitCtx.RemoteURLs) > 0 {
			remote = gitCtx.RemoteURLs[0]
		}
		fmt.Fprintf(os.Stderr, "Git: %s @ %s (%s)\n", gitCtx.CurrentBranch, commitShort, remote)
	}
	fmt.Fprintln(os.Stderr)

	// ── 2. Discover files ─────────────────────────────────────────────────
	files, err := scan.WalkForScanFiles(scan.WalkOptions{
		RootPath: scanPath,
		MaxDepth: depth,
		Excludes: excludes,
	})
	if err != nil {
		return fmt.Errorf("failed to scan directory: %w", err)
	}
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "No scannable files detected.")
		return nil
	}

	// ── 3. Display detected files ─────────────────────────────────────────
	fmt.Fprintln(os.Stderr, "Detected files:")
	var supportedFiles []scan.DetectedFile
	for _, f := range files {
		switch f.FileType {
		case scan.FileTypeManifest:
			lockStr := ""
			if f.ManifestInfo.IsLock {
				lockStr = "lock"
			}
			supportedStr := ""
			if !f.Supported {
				supportedStr = " [not supported]"
			}
			fmt.Fprintf(os.Stderr, "  %-40s manifest    %-10s (%s) %s%s\n",
				f.RelPath, f.ManifestInfo.Ecosystem, f.ManifestInfo.Language, lockStr, supportedStr)
		case scan.FileTypeSPDX:
			fmt.Fprintf(os.Stderr, "  %-40s spdx        v%-9s\n", f.RelPath, f.SBOMVersion)
		case scan.FileTypeCycloneDX:
			cdxBom, cdxErr := parseCDXForScan(f.Path)
			if cdxErr == nil && isVulnetixSCA(cdxBom) {
				fmt.Fprintf(os.Stderr, "  %-40s %s\n", f.RelPath,
					display.Teal(t, "[skipped — produced by vulnetix-sca]"))
				continue
			}
			if cdxErr == nil && cdxBom != nil && len(cdxBom.Components) > 0 {
				fmt.Fprintf(os.Stderr, "  %-40s cyclonedx   v%-8s (%d comp, %d vulns)\n",
					f.RelPath, f.SBOMVersion, len(cdxBom.Components), len(cdxBom.Vulnerabilities))
				f.Supported = true
				supportedFiles = append(supportedFiles, f)
			} else {
				fmt.Fprintf(os.Stderr, "  %-40s cyclonedx   v%-9s\n", f.RelPath, f.SBOMVersion)
			}
		}
		if f.Supported && f.FileType == scan.FileTypeManifest {
			supportedFiles = append(supportedFiles, f)
		}
	}

	if len(supportedFiles) == 0 {
		fmt.Fprintln(os.Stderr, "\nNo supported manifest files found for scanning.")
		return nil
	}

	// ── 4. Parse manifests (local only, no network) ───────────────────────
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Parsing manifests (local):")
	totalPkgs := 0
	for _, f := range supportedFiles {
		// CDX input files: extract components as packages.
		if f.FileType == scan.FileTypeCycloneDX {
			cdxBom, err := parseCDXForScan(f.Path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  %-40s parse error: %v\n", f.RelPath, err)
				continue
			}
			pkgs := buildPackagesFromCDX(cdxBom.Components, f.RelPath)
			scopeCounts := map[string]int{}
			for _, p := range pkgs {
				scopeCounts[p.Scope]++
			}
			fmt.Fprintf(os.Stderr, "  %-40s %d packages%s\n",
				f.RelPath, len(pkgs), formatScopeCounts(scopeCounts))
			totalPkgs += len(pkgs)
			continue
		}
		if f.ManifestInfo == nil {
			continue
		}
		pkgs, err := scan.ParseManifestWithScope(f.Path, f.ManifestInfo.Type)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %-40s parse error: %v\n", f.RelPath, err)
			continue
		}
		for i := range pkgs {
			pkgs[i].SourceFile = f.RelPath
		}
		scopeCounts := map[string]int{}
		for _, p := range pkgs {
			scopeCounts[p.Scope]++
		}
		fmt.Fprintf(os.Stderr, "  %-40s %d packages%s\n",
			f.RelPath, len(pkgs), formatScopeCounts(scopeCounts))
		totalPkgs += len(pkgs)
	}

	// ── 5. Dry-run summary ────────────────────────────────────────────────
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "%s %d supported file(s), %s total — ",
		display.CheckMark(t), len(supportedFiles), pluralise("package", totalPkgs))
	fmt.Fprintln(os.Stderr, display.Muted(t, "VDB queries skipped (dry run)"))

	if severityThreshold != "" {
		fmt.Fprintf(os.Stderr, "%s --severity %s noted (evaluated from memory if available)\n",
			display.Muted(t, "\u2139"), severityThreshold)
	}

	// ── 6. Check memory ───────────────────────────────────────────────────
	vulnetixDir := filepath.Join(scanPath, ".vulnetix")
	sbomPath := filepath.Join(vulnetixDir, "sbom.cdx.json")

	if _, statErr := os.Stat(sbomPath); os.IsNotExist(statErr) {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "%s No memory found at %s (run 'vulnetix scan' to create it)\n",
			display.Muted(t, "\u2139"), sbomPath)
		return nil
	}

	// Render memory — no fresh* flags so zero API calls.
	relSBOM, relErr := filepath.Rel(scanPath, sbomPath)
	if relErr != nil {
		relSBOM = sbomPath
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "%s Found memory at %s — rendering previous results:\n",
		display.CheckMark(t), relSBOM)
	fmt.Fprintln(os.Stderr)

	// Resolve a path relative to cwd so LoadFromMemory resolves .vulnetix/ correctly.
	memRoot, relErr := filepath.Rel(".", scanPath)
	if relErr != nil || memRoot == "" {
		memRoot = "."
	}
	return LoadFromMemory(memRoot, false, false, false)
}

// ---------------------------------------------------------------------------
// Pretty output
// ---------------------------------------------------------------------------

// printPrettyScanSummary prints a single threat-ordered vulnerability table
// across all manifest files. The first column shows the manifest file path
// (in teal) only on its first row; subsequent rows for the same file leave it
// blank. Exploit and remediation detail sections follow the table.
func printPrettyScanSummary(
	enrichedVulns []scan.EnrichedVuln,
	manifestGroups []scan.ManifestGroup,
	allPackages []scan.ScopedPackage,
	showPaths bool,
	noExploits bool,
	noRemediation bool,
	sbomPath, vulnetixDir, rulesPath string,
	severityThreshold string,
) {
	t := display.NewTerminal()
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, display.Divider(t))

	// Index vulns by source file for manifest grouping.
	vulnsBySource := map[string][]scan.EnrichedVuln{}
	for _, v := range enrichedVulns {
		vulnsBySource[v.SourceFile] = append(vulnsBySource[v.SourceFile], v)
	}

	sort.Slice(manifestGroups, func(i, j int) bool {
		return manifestGroups[i].Dir < manifestGroups[j].Dir
	})

	totalVulns := len(enrichedVulns)

	// Pre-compute per-group data (dedup + sort) so we only iterate once.
	type mgResult struct {
		mg           scan.ManifestGroup
		primaryFile  string
		dedupedVulns []scan.EnrichedVuln
	}
	type pathEntry struct {
		pkgName string
		chain   []string
	}

	prepared := make([]mgResult, 0, len(manifestGroups))
	for _, mg := range manifestGroups {
		var groupVulns []scan.EnrichedVuln
		for _, file := range mg.Files {
			groupVulns = append(groupVulns, vulnsBySource[file]...)
		}
		seen := map[string]bool{}
		var deduped []scan.EnrichedVuln
		for _, v := range groupVulns {
			key := v.CveID + "::" + v.PackageName
			if !seen[key] {
				seen[key] = true
				deduped = append(deduped, v)
			}
		}
		sortByThreat(deduped)
		sort.Strings(mg.Files)
		prepared = append(prepared, mgResult{mg: mg, primaryFile: mg.Files[0], dedupedVulns: deduped})
	}

	// ── Unified table columns ─────────────────────────────────────────────
	// "File" is the first column; non-empty cells are coloured teal.
	cols := []display.Column{
		{Header: "File", MinWidth: 20, MaxWidth: 50, Color: func(s string) string {
			if strings.TrimSpace(s) == "" {
				return s
			}
			return display.Teal(t, s)
		}},
		{Header: "Vuln ID", MinWidth: 16, MaxWidth: 28},
		{Header: "Package", MinWidth: 14, MaxWidth: 36},
		{Header: "Mal", MinWidth: 3, MaxWidth: 3},
		{Header: "MaxSev", MinWidth: 6, MaxWidth: 10},
		{Header: "CVSS", MinWidth: 4, MaxWidth: 6, Align: display.AlignRight},
		{Header: "CVSSSev", MinWidth: 4, MaxWidth: 8},
		{Header: "EPSS", MinWidth: 4, MaxWidth: 10, Align: display.AlignRight},
		{Header: "EPSSSev", MinWidth: 4, MaxWidth: 8},
		{Header: "SSVC", MinWidth: 4, MaxWidth: 8},
		{Header: "SSVCSev", MinWidth: 4, MaxWidth: 8},
		{Header: "CESS", MinWidth: 4, MaxWidth: 8, Align: display.AlignRight},
		{Header: "CESSev", MinWidth: 4, MaxWidth: 8},
		{Header: "Expl", MinWidth: 4, MaxWidth: 5, Align: display.AlignRight},
		{Header: "Fix", MinWidth: 3, MaxWidth: 20},
	}

	var allRows [][]string
	var allPaths []pathEntry

	// ── First pass: build unified table rows ──────────────────────────────
	for _, res := range prepared {
		mg := res.mg
		primaryFile := res.primaryFile
		dedupedVulns := res.dedupedVulns

		if len(dedupedVulns) == 0 {
			// Sentinel row so the file still appears in the table.
			row := make([]string, 15)
			row[0] = primaryFile
			row[1] = "(no vulnerabilities)"
			allRows = append(allRows, row)
			continue
		}

		for i, v := range dedupedVulns {
			// File column: filled only for the first row of each group.
			fileCell := ""
			if i == 0 {
				fileCell = primaryFile
			}

			vulnID := v.CveID
			if v.InCisaKev {
				vulnID += " [KEV]"
			}

			pkg := v.PackageName + " " + v.PackageVer
			if v.Scope != "" && v.Scope != scan.ScopeProduction {
				pkg += " [" + v.Scope + "]"
			}
			if mg.Graph != nil && !mg.Graph.IsDirect(v.PackageName) {
				pkg += " *"
			}

			mal := ""
			if v.IsMalicious {
				mal = "YES"
			}

			maxSev := strings.ToUpper(v.MaxSeverity)
			if maxSev == "" || maxSev == "UNSCORED" {
				maxSev = strings.ToUpper(v.Severity)
			}

			cvss, cvssSev := "", ""
			if v.CVSSScore > 0 {
				cvss = fmt.Sprintf("%.1f", v.CVSSScore)
				cvssSev = strings.ToUpper(v.CVSSSeverity)
			} else if v.Score > 0 {
				cvss = fmt.Sprintf("%.1f", v.Score)
				cvssSev = strings.ToUpper(v.Severity)
			}

			epss, epssSev := "", ""
			if v.EPSSScore > 0 {
				epss = fmt.Sprintf("%.4f", v.EPSSScore)
				epssSev = strings.ToUpper(v.EPSSSeverity)
			}

			ssvc := v.SSVCDecision
			ssvcSev := ""
			if v.SSVCSeverity != "" && v.SSVCSeverity != "unscored" {
				ssvcSev = strings.ToUpper(v.SSVCSeverity)
			}

			cess, cesSev := "", ""
			if v.CoalitionESS > 0 {
				cess = fmt.Sprintf("%.4f", v.CoalitionESS)
				cesSev = strings.ToUpper(v.CESSeverity)
			}

			expl := "0"
			if v.ExploitIntel != nil && v.ExploitIntel.ExploitCount > 0 {
				expl = fmt.Sprintf("%d", v.ExploitIntel.ExploitCount)
			}

			fix := ""
			if v.Remediation != nil && v.Remediation.FixVersion != "" {
				fix = v.Remediation.FixVersion
			} else if v.FixAvailability != "" {
				switch strings.ToLower(v.FixAvailability) {
				case "available", "fix_available":
					fix = "available"
				case "partial":
					fix = "partial"
				case "no_fix":
					fix = "no fix"
				default:
					fix = v.FixAvailability
				}
			}

			allRows = append(allRows, []string{
				fileCell, vulnID, pkg, mal, maxSev,
				cvss, cvssSev, epss, epssSev,
				ssvc, ssvcSev, cess, cesSev, expl, fix,
			})

			if showPaths && mg.Graph != nil && !mg.Graph.IsDirect(v.PackageName) {
				if chain := mg.Graph.FindPath(v.PackageName); len(chain) > 1 {
					allPaths = append(allPaths, pathEntry{pkgName: v.PackageName, chain: chain})
				}
			}
		}
	}

	// ── Print unified table ───────────────────────────────────────────────
	fmt.Fprintln(os.Stdout)
	if len(allRows) > 0 {
		fmt.Fprintln(os.Stdout, display.Table(t, cols, allRows))
		fmt.Fprintln(os.Stdout, display.Muted(t, "  * = transitive dependency"))
	}

	// ── Dependency paths ──────────────────────────────────────────────────
	if showPaths && len(allPaths) > 0 {
		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, display.Subheader(t, "Dependency Paths"))
		seenPaths := map[string]bool{}
		for _, p := range allPaths {
			if seenPaths[p.pkgName] {
				continue
			}
			seenPaths[p.pkgName] = true
			fmt.Fprintf(os.Stdout, "  %s\n", display.Muted(t, strings.Join(p.chain, " → ")))
		}
	}

	fmt.Fprintln(os.Stdout)

	// ── Second pass: exploits + remediation per group ─────────────────────
	for _, res := range prepared {
		dedupedVulns := res.dedupedVulns
		if len(dedupedVulns) == 0 {
			continue
		}

		// ── Exploits detail ───────────────────────────────────────────────
		if !noExploits {
			hasExploits := false
			for _, v := range dedupedVulns {
				if v.ExploitIntel != nil && v.ExploitIntel.ExploitCount > 0 {
					hasExploits = true
					break
				}
			}
			if hasExploits {
				fmt.Fprintln(os.Stdout)
				fmt.Fprintln(os.Stdout, display.Subheader(t, "Exploits"))
				for _, v := range dedupedVulns {
					if v.ExploitIntel == nil || v.ExploitIntel.ExploitCount == 0 {
						continue
					}
					ei := v.ExploitIntel
					line := fmt.Sprintf("  %s  %d exploit(s)", display.Bold(t, v.CveID), ei.ExploitCount)
					if len(ei.Sources) > 0 {
						line += "  sources: " + strings.Join(ei.Sources, ", ")
					}
					if ei.HighestMaturity != "" {
						line += "  maturity: " + ei.HighestMaturity
					}
					if ei.HasWeaponized {
						line += "  " + display.Accent(t, "[WEAPONIZED]")
					}
					fmt.Fprintln(os.Stdout, line)
				}
			}
		}

		// ── Remediation detail ────────────────────────────────────────────
		if !noRemediation {
			hasRemediation := false
			for _, v := range dedupedVulns {
				if v.Remediation != nil && (v.Remediation.FixVersion != "" || len(v.Remediation.Actions) > 0 || v.FixAvailability != "") {
					hasRemediation = true
					break
				}
			}
			if hasRemediation {
				fmt.Fprintln(os.Stdout)
				fmt.Fprintln(os.Stdout, display.Subheader(t, "Remediation"))

				// Group vulns by package so shared remediations are shown once.
				type remGroup struct {
					vulnIDs  []string
					pkg      string
					ver      string
					rem      *scan.RemediationInfo
					fixAvail string
				}
				remByPkg := map[string]*remGroup{}
				var remOrder []string

				for _, v := range dedupedVulns {
					if v.Remediation == nil && v.FixAvailability == "" {
						continue
					}
					// Key by package + fix version/availability so identical remediations merge.
					fixKey := ""
					if v.Remediation != nil {
						fixKey = v.Remediation.FixVersion
					}
					if fixKey == "" {
						fixKey = v.FixAvailability
					}
					key := v.PackageName + "::" + fixKey

					if rg, ok := remByPkg[key]; ok {
						rg.vulnIDs = append(rg.vulnIDs, v.CveID)
					} else {
						remByPkg[key] = &remGroup{
							vulnIDs:  []string{v.CveID},
							pkg:      v.PackageName,
							ver:      v.PackageVer,
							rem:      v.Remediation,
							fixAvail: v.FixAvailability,
						}
						remOrder = append(remOrder, key)
					}
				}

				for _, key := range remOrder {
					rg := remByPkg[key]

					// Vuln IDs this remediation applies to.
					ids := strings.Join(rg.vulnIDs, ", ")
					fmt.Fprintf(os.Stdout, "\n  %s  %s %s\n",
						display.Bold(t, rg.pkg+" "+rg.ver), display.Muted(t, "→"), ids)

					// Fix version or availability.
					if rg.rem != nil && rg.rem.FixVersion != "" {
						fmt.Fprintf(os.Stdout, "    Upgrade to: %s\n", display.Bold(t, rg.rem.FixVersion))
					}
					if rg.rem != nil && rg.rem.FixAvailability != "" {
						fmt.Fprintf(os.Stdout, "    Fix status: %s\n", rg.rem.FixAvailability)
					} else if rg.fixAvail != "" {
						fmt.Fprintf(os.Stdout, "    Fix status: %s\n", rg.fixAvail)
					}

					// Actions (deduplicated and collapsed).
					if rg.rem != nil && len(rg.rem.Actions) > 0 {
						printCollapsedActions(t, rg.rem.Actions)
					}
				}
			}
		}
	}

	fmt.Fprintln(os.Stdout, display.Divider(t))

	// Summary line.
	totalPkgs := len(countUniqueMap(allPackages))
	summary := fmt.Sprintf("  %d packages | %s", totalPkgs, pluralise("vulnerability", totalVulns))
	fmt.Fprintln(os.Stdout, display.Bold(t, summary))
	fmt.Fprintln(os.Stdout)

	// Artefact paths.
	fmt.Fprintf(os.Stdout, "  %s BOM:    %s\n", display.CheckMark(t), sbomPath)
	fmt.Fprintf(os.Stdout, "  %s Memory: %s\n", display.CheckMark(t), filepath.Join(vulnetixDir, memory.FileName))
	if rulesPath != "" {
		fmt.Fprintf(os.Stdout, "  %s Rules:  %s\n", display.CheckMark(t), rulesPath)
	}
	fmt.Fprintln(os.Stdout)
}

// printCollapsedActions deduplicates actions and collapses groups that share a
// common prefix (e.g., "Apply Red Hat patch RHSA-2024:XXXX" × 33 → one line
// listing all advisory IDs).
func printCollapsedActions(t *display.Terminal, actions []string) {
	// Deduplicate.
	seen := map[string]bool{}
	var unique []string
	for _, a := range actions {
		if !seen[a] {
			seen[a] = true
			unique = append(unique, a)
		}
	}

	if len(unique) <= 3 {
		for _, a := range unique {
			fmt.Fprintf(os.Stdout, "    • %s\n", a)
		}
		return
	}

	// Try to find a shared prefix to collapse.
	// Group actions by everything before the last whitespace-delimited token.
	type group struct {
		prefix string
		ids    []string
	}
	groups := map[string]*group{}
	var groupOrder []string

	for _, a := range unique {
		lastSpace := strings.LastIndex(a, " ")
		if lastSpace <= 0 {
			// No prefix to split — print as-is.
			fmt.Fprintf(os.Stdout, "    • %s\n", a)
			continue
		}
		prefix := a[:lastSpace]
		id := a[lastSpace+1:]
		if g, ok := groups[prefix]; ok {
			g.ids = append(g.ids, id)
		} else {
			groups[prefix] = &group{prefix: prefix, ids: []string{id}}
			groupOrder = append(groupOrder, prefix)
		}
	}

	for _, prefix := range groupOrder {
		g := groups[prefix]
		if len(g.ids) <= 3 {
			for _, id := range g.ids {
				fmt.Fprintf(os.Stdout, "    • %s %s\n", prefix, id)
			}
		} else {
			fmt.Fprintf(os.Stdout, "    • %s (%d advisories)\n", prefix, len(g.ids))
			// Print IDs as a wrapped comma-separated list.
			idList := strings.Join(g.ids, ", ")
			fmt.Fprintf(os.Stdout, "      %s\n", display.Muted(t, idList))
		}
	}
}

// sortByThreat sorts enriched vulns by: malware > SSVC Act > weaponised > x_threatExposure.
func sortByThreat(vulns []scan.EnrichedVuln) {
	sort.SliceStable(vulns, func(i, j int) bool {
		a, b := vulns[i], vulns[j]
		if a.IsMalicious != b.IsMalicious {
			return a.IsMalicious
		}
		aAct := strings.EqualFold(a.SSVCDecision, "Act")
		bAct := strings.EqualFold(b.SSVCDecision, "Act")
		if aAct != bAct {
			return aAct
		}
		aWeapon := a.ExploitIntel != nil && a.ExploitIntel.HasWeaponized
		bWeapon := b.ExploitIntel != nil && b.ExploitIntel.HasWeaponized
		if aWeapon != bWeapon {
			return aWeapon
		}
		return a.ThreatExposure > b.ThreatExposure
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// printLookupSummary writes a concise VDB lookup summary to stderr.
// It always shows rate-limit status when available, and lists any skipped,
// failed, or cancelled packages so the user knows what was not checked.
// When hasPartialResults is true, the error is printed inline (the caller
// will continue); when false the caller returns the error to Cobra, so we
// skip it here to avoid duplication.
func printLookupSummary(client *vdb.Client, stats *scan.LookupStats, lookupErr error, hasPartialResults bool) {
	if stats == nil {
		return
	}

	// Rate-limit info (shown whenever the API returned headers).
	if rl := client.LastRateLimit; rl != nil && rl.Present {
		fmt.Fprintf(os.Stderr, "  Rate limit: %d/%d req/min remaining (resets %s)",
			rl.Remaining, rl.MinuteLimit, humanReset(rl.Reset))
		if rl.WeekLimit > 0 {
			fmt.Fprintf(os.Stderr, ", %d/%d req/week remaining (resets %s)",
				rl.WeekRemaining, rl.WeekLimit, humanReset(rl.WeekReset))
		}
		fmt.Fprintln(os.Stderr)
	}

	// Nothing to report beyond rate limits when everything succeeded.
	if stats.Failed == 0 && stats.Skipped == 0 && stats.Cancelled == 0 {
		return
	}

	// Build a concise one-line summary of non-successful outcomes.
	var parts []string
	if stats.Succeeded > 0 {
		parts = append(parts, fmt.Sprintf("%d succeeded", stats.Succeeded))
	}
	if stats.Failed > 0 {
		parts = append(parts, fmt.Sprintf("%d failed", stats.Failed))
	}
	if stats.Cancelled > 0 {
		parts = append(parts, fmt.Sprintf("%d cancelled", stats.Cancelled))
	}
	if stats.Skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d skipped (name < 3 chars)", stats.Skipped))
	}
	fmt.Fprintf(os.Stderr, "  VDB lookup: %s of %d\n", strings.Join(parts, ", "), stats.Total)

	if lookupErr != nil && hasPartialResults {
		fmt.Fprintf(os.Stderr, "  Error: %v\n", lookupErr)
	}
}

// humanReset formats a rate-limit reset value into a concise human-readable
// string. The value may be a Unix epoch timestamp (>1_000_000_000) or a
// relative number of seconds.
func humanReset(val int) string {
	if val <= 0 {
		return "now"
	}
	secs := val
	// Heuristic: values above 1 billion are Unix timestamps, not durations.
	if val > 1_000_000_000 {
		secs = val - int(time.Now().Unix())
		if secs <= 0 {
			return "now"
		}
	}
	if secs < 60 {
		return fmt.Sprintf("in %ds", secs)
	}
	if secs < 3600 {
		return fmt.Sprintf("in %dm", secs/60)
	}
	h := secs / 3600
	m := (secs % 3600) / 60
	if m == 0 {
		return fmt.Sprintf("in %dh", h)
	}
	return fmt.Sprintf("in %dh%dm", h, m)
}

// newSearchClient creates a VDB v1 client for package search using stored credentials.
// Falls back to embedded community credentials when no user credentials are configured.
func newSearchClient() *vdb.Client {
	creds := vdbCreds
	if creds == nil {
		// resolveVDBCredentials(false) should have already set community creds,
		// but guard here in case it was skipped.
		creds = auth.CommunityCredentials()
	}
	client := vdb.NewClientFromCredentials(creds)
	client.APIVersion = "/v1"

	if dc, err := cache.NewDiskCache(version); err == nil {
		client.Cache = dc
	}
	return client
}

// newEnrichmentClient creates a VDB v2 client for enrichment (affected ranges,
// remediation plans). Shares the same disk cache as the v1 client — cache keys
// incorporate the API version so entries don't collide.
func newEnrichmentClient() *vdb.Client {
	creds := vdbCreds
	if creds == nil {
		creds = auth.CommunityCredentials()
	}
	client := vdb.NewClientFromCredentials(creds)
	client.APIVersion = "/v2"

	if dc, err := cache.NewDiskCache(version); err == nil {
		client.Cache = dc
	}
	return client
}

// writeIDSRulesFile writes collected IDS rules to a file with CVE comment headers.
func writeIDSRulesFile(path string, rules []scan.IDSRule) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	var sb strings.Builder
	lastCVE := ""
	for _, r := range rules {
		if r.CveID != lastCVE {
			if lastCVE != "" {
				sb.WriteString("\n")
			}
			sb.WriteString(fmt.Sprintf("# %s\n", r.CveID))
			lastCVE = r.CveID
		}
		sb.WriteString(r.Content)
		sb.WriteString("\n")
	}
	return os.WriteFile(path, []byte(sb.String()), 0o644)
}

// formatScopeCounts renders a parenthetical scope breakdown string.
func formatScopeCounts(counts map[string]int) string {
	if len(counts) == 0 {
		return ""
	}
	order := []string{
		scan.ScopeProduction, scan.ScopeDevelopment, scan.ScopeTest,
		scan.ScopePeer, scan.ScopeOptional, scan.ScopeProvided,
		scan.ScopeRuntime, scan.ScopeSystem,
	}
	var parts []string
	for _, s := range order {
		if n, ok := counts[s]; ok && n > 0 {
			parts = append(parts, fmt.Sprintf("%s: %d", s, n))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

// countUniquePackages counts (name, ecosystem) unique pairs.
func countUniquePackages(packages []scan.ScopedPackage) int {
	seen := map[string]bool{}
	for _, p := range packages {
		if len(p.Name) >= 3 {
			seen[p.Name+"::"+p.Ecosystem] = true
		}
	}
	return len(seen)
}

// countUniqueMap returns a map of "name::ecosystem" → package (for dedup counting in display).
// Applies the same len(name) >= 3 filter as countUniquePackages so the counts agree.
func countUniqueMap(packages []scan.ScopedPackage) map[string]scan.ScopedPackage {
	m := map[string]scan.ScopedPackage{}
	for _, p := range packages {
		if len(p.Name) >= 3 {
			key := p.Name + "::" + p.Ecosystem
			if _, exists := m[key]; !exists {
				m[key] = p
			}
		}
	}
	return m
}

// countSeverities tallies vulns by severity bucket.
func countSeverities(vulns []scan.VulnFinding) map[string]int {
	counts := map[string]int{}
	for _, v := range vulns {
		counts[strings.ToLower(v.Severity)]++
	}
	return counts
}

// pluralise returns the correctly pluralised count+word string.
// It handles irregular plurals explicitly rather than blindly appending "s".
func pluralise(word string, n int) string {
	if n == 1 {
		return "1 " + word
	}
	plurals := map[string]string{
		"vulnerability": "vulnerabilities",
		"dependency":    "dependencies",
		"advisory":      "advisories",
		"library":       "libraries",
		"entry":         "entries",
		"match":         "matches",
	}
	if plural, ok := plurals[word]; ok {
		return fmt.Sprintf("%d %s", n, plural)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// renderProgressBar renders a Unicode block progress bar of the given width.
func renderProgressBar(done, total, width int) string {
	if total == 0 {
		return strings.Repeat("░", width)
	}
	filled := done * width / total
	if filled > width {
		filled = width
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

// buildScanRecord constructs a memory.ScanRecord from scan results.
func buildScanRecord(
	results []cdx.LocalScanResult,
	allVulns []scan.VulnFinding,
	allFiles []scan.DetectedFile,
	rootPath string,
	gitCtx *gitctx.GitContext,
	sysInfo *gitctx.SystemInfo,
	sbomPath string,
) memory.ScanRecord {
	rec := memory.ScanRecord{
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Path:         rootPath,
		FilesScanned: len(results),
		Vulns:        len(allVulns),
	}

	if gitCtx != nil {
		rec.GitBranch = gitCtx.CurrentBranch
		rec.GitCommit = gitCtx.CurrentCommit
		if len(gitCtx.RemoteURLs) > 0 {
			rec.GitRemote = gitCtx.RemoteURLs[0]
		}
	}

	// Total unique packages.
	pkgSet := map[string]bool{}
	for _, r := range results {
		for _, p := range r.Packages {
			pkgSet[p.Name+"@"+p.Version] = true
		}
	}
	rec.Packages = len(pkgSet)

	// Severity counts.
	for _, v := range allVulns {
		switch strings.ToLower(v.Severity) {
		case "critical":
			rec.Critical++
		case "high":
			rec.High++
		case "medium":
			rec.Medium++
		case "low":
			rec.Low++
		}
	}

	// Scope breakdown.
	scopePkgs := map[string]map[string]bool{}
	scopeVulns := map[string]int{}
	for _, r := range results {
		for _, p := range r.Packages {
			if scopePkgs[p.Scope] == nil {
				scopePkgs[p.Scope] = map[string]bool{}
			}
			scopePkgs[p.Scope][p.Name+"@"+p.Version] = true
		}
	}
	for _, v := range allVulns {
		scopeVulns[v.Scope]++
	}
	rec.ScopeBreakdown = map[string]memory.ScopeStats{}
	for scope, pset := range scopePkgs {
		rec.ScopeBreakdown[scope] = memory.ScopeStats{
			Packages: len(pset),
			Vulns:    scopeVulns[scope],
		}
	}

	// Use path relative to cwd for the sbom path in memory.
	rel, err := filepath.Rel(rootPath, sbomPath)
	if err == nil {
		rec.SBOMPath = rel
	} else {
		rec.SBOMPath = sbomPath
	}

	return rec
}

// writeBOMToFile writes a CycloneDX BOM as JSON to the given path, creating directories as needed.
func writeBOMToFile(bom *cdx.BOM, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return bom.WriteJSON(f)
}

// writeRawLocalJSON writes scan findings as a raw JSON document to stdout.
func writeRawLocalJSON(results []cdx.LocalScanResult) error {
	type vulnOut struct {
		CveID       string  `json:"cveId"`
		PackageName string  `json:"packageName"`
		PackageVer  string  `json:"packageVersion"`
		Ecosystem   string  `json:"ecosystem"`
		Scope       string  `json:"scope"`
		Severity    string  `json:"severity"`
		Score       float64 `json:"score"`
		SourceFile  string  `json:"sourceFile"`
	}
	type fileOut struct {
		File  string    `json:"file"`
		Vulns []vulnOut `json:"vulnerabilities"`
	}

	out := make([]fileOut, 0, len(results))
	for _, r := range results {
		fo := fileOut{File: r.File.RelPath}
		for _, v := range r.Vulns {
			fo.Vulns = append(fo.Vulns, vulnOut{
				CveID:       v.CveID,
				PackageName: v.PackageName,
				PackageVer:  v.PackageVer,
				Ecosystem:   v.Ecosystem,
				Scope:       v.Scope,
				Severity:    v.Severity,
				Score:       v.Score,
				SourceFile:  v.SourceFile,
			})
		}
		out = append(out, fo)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}

// pollScanResultsLegacy is the original sequential polling used by scan status subcommand.
func pollScanResultsLegacy(client *vdb.Client, scanIDs []string, intervalSec int, output string) error {
	pending := make(map[string]bool)
	for _, id := range scanIDs {
		pending[id] = true
	}

	allResults := make(map[string]interface{})
	interval := time.Duration(intervalSec) * time.Second

	for len(pending) > 0 {
		for id := range pending {
			result, err := client.V2ScanStatus(id)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  [%s] error: %v\n", id, err)
				delete(pending, id)
				allResults[id] = map[string]interface{}{"error": err.Error()}
				continue
			}

			status, _ := result["status"].(string)
			switch status {
			case "complete", "completed", "error", "failed":
				fmt.Fprintf(os.Stderr, "  [%s] %s\n", id, status)
				delete(pending, id)
				allResults[id] = result
			default:
				fmt.Fprintf(os.Stderr, "  [%s] %s...\n", id, status)
			}
		}

		if len(pending) > 0 {
			time.Sleep(interval)
		}
	}

	if len(allResults) == 1 {
		for _, v := range allResults {
			return printOutput(v, output)
		}
	}
	return printOutput(allResults, output)
}

// ---------------------------------------------------------------------------
// display.NewTerminal shim — Terminal is constructed without cmd context here.
// ---------------------------------------------------------------------------

// parseCDXForScan loads and parses a CycloneDX JSON file for use as a seed BOM.
func parseCDXForScan(path string) (*cdx.BOM, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, err
	}
	return &bom, nil
}

// isVulnetixSCA checks whether the BOM was produced by vulnetix-sca.
func isVulnetixSCA(bom *cdx.BOM) bool {
	if bom == nil {
		return false
	}
	if bom.Metadata != nil && bom.Metadata.Tools != nil {
		for _, tc := range bom.Metadata.Tools.Components {
			if tc.Name == "vulnetix-sca" {
				return true
			}
		}
	}
	return false
}

// vulnetixSCAVersion returns the version string of the vulnetix-sca tool
// component in the BOM metadata, or "" if not present.
func vulnetixSCAVersion(bom *cdx.BOM) string {
	if bom == nil || bom.Metadata == nil || bom.Metadata.Tools == nil {
		return ""
	}
	for _, tc := range bom.Metadata.Tools.Components {
		if tc.Name == "vulnetix-sca" {
			return tc.Version
		}
	}
	return ""
}

// buildPackagesFromCDX converts CDX components to ScopedPackage entries,
// attributing them to the given sourceFile.
func buildPackagesFromCDX(components []cdx.Component, sourceFile string) []scan.ScopedPackage {
	pkgs := make([]scan.ScopedPackage, 0, len(components))
	for _, c := range components {
		pkg := buildPkgFromComponent(c)
		pkg.SourceFile = sourceFile
		pkgs = append(pkgs, pkg)
	}
	return pkgs
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.AddCommand(scanStatusCmd)

	// Scan flags
	scanCmd.Flags().String("path", ".", "Directory to scan")
	scanCmd.Flags().Int("depth", 3, "Max recursion depth")
	scanCmd.Flags().StringArray("exclude", nil, "Exclude paths matching glob (repeatable)")
	scanCmd.Flags().StringP("format", "f", "", "Output format: cdx17 (default), cdx16, json (stdout); omit for pretty summary")
	scanCmd.Flags().Int("concurrency", 5, "Max concurrent VDB queries")
	scanCmd.Flags().Bool("no-progress", false, "Suppress progress bar")
	scanCmd.Flags().Bool("paths", false, "Show full transitive dependency paths (requires Go toolchain for Go modules)")
	scanCmd.Flags().Bool("no-exploits", false, "Suppress detailed exploit intelligence section")
	scanCmd.Flags().Bool("no-remediation", false, "Suppress detailed remediation section")
	scanCmd.Flags().String("severity", "", "Exit with code 1 if any vulnerability meets or exceeds this severity (low, medium, high, critical). Severity is coerced from all available scoring sources (CVSS, EPSS, Coalition ESS, SSVC).")

	// --dry-run flag
	scanCmd.Flags().Bool("dry-run", false, "Detect files and parse packages locally, check memory, then exit — zero API calls")

	// --from-memory and --fresh-* flags
	scanCmd.Flags().Bool("from-memory", false, "Reconstruct scan pretty output from .vulnetix/sbom.cdx.json without API calls")
	scanCmd.Flags().Bool("fresh-exploits", false, "With --from-memory: fetch latest exploit intel from API")
	scanCmd.Flags().Bool("fresh-advisories", false, "With --from-memory: fetch latest remediation plans from API")
	scanCmd.Flags().Bool("fresh-vulns", false, "With --from-memory: re-fetch affected version checks and latest scoring from API")

	_ = scanCmd.RegisterFlagCompletionFunc("format", cobra.FixedCompletions(
		[]string{"cdx17", "cdx16", "json"}, cobra.ShellCompDirectiveNoFileComp))
	_ = scanCmd.RegisterFlagCompletionFunc("severity", cobra.FixedCompletions(
		[]string{"low", "medium", "high", "critical"}, cobra.ShellCompDirectiveNoFileComp))
	_ = scanCmd.MarkFlagDirname("path")

	// scan status flags
	scanStatusCmd.Flags().Bool("poll", false, "Poll until complete")
	scanStatusCmd.Flags().Int("poll-interval", 5, "Polling interval in seconds")
	scanStatusCmd.Flags().StringP("output", "o", "pretty", "Output format (json, pretty)")
	_ = scanStatusCmd.RegisterFlagCompletionFunc("output", cobra.FixedCompletions(
		[]string{"json", "pretty"}, cobra.ShellCompDirectiveNoFileComp))
}

// Ensure tui package is imported (used indirectly for color constants via display).
var _ = tui.ColorAccent
