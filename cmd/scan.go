package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/internal/analytics"
	"github.com/vulnetix/cli/pkg/auth"
	"github.com/vulnetix/cli/pkg/cache"
	"github.com/vulnetix/cli/internal/cdx"
	"github.com/vulnetix/cli/internal/display"
	"github.com/vulnetix/cli/internal/gitctx"
	"github.com/vulnetix/cli/internal/license"
	"github.com/vulnetix/cli/internal/memory"
	"github.com/vulnetix/cli/internal/sast"
	"github.com/vulnetix/cli/internal/scan"
	"github.com/vulnetix/cli/internal/update"
	"github.com/vulnetix/cli/pkg/tty"
	"github.com/vulnetix/cli/internal/tui"
	"github.com/vulnetix/cli/pkg/vdb"
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

// PolicyBreachError is implemented by all quality-gate breach errors.
// Execute() uses this interface to suppress redundant error printing —
// the command itself has already printed the breach details.
type PolicyBreachError interface {
	error
	isPolicyBreach()
}

// GateBreach captures one quality gate's failure details.
type GateBreach struct {
	Gate    string // "malware" | "exploits" | "severity" | "eol"
	Count   int
	Message string // pre-formatted, ready to print
}

// MultiPolicyBreachError is returned when one or more quality gates are breached.
type MultiPolicyBreachError struct {
	Breaches []GateBreach
}

func (e *MultiPolicyBreachError) isPolicyBreach() {}
func (e *MultiPolicyBreachError) Error() string {
	parts := make([]string, 0, len(e.Breaches))
	for _, b := range e.Breaches {
		parts = append(parts, b.Message)
	}
	return "quality gate(s) breached: " + strings.Join(parts, "; ")
}

// outputTarget describes one --output value, classified as either a stdout format
// or a file path.
type outputTarget struct {
	stdoutFmt string // "json-cyclonedx" or "json-sarif" (empty if file)
	filePath  string // non-empty if writing to a file
	fileKind  string // "cdx" or "sarif" — inferred from extension or stdoutFmt
}

// outputConfig holds the parsed --output flags.
type outputConfig struct {
	targets    []outputTarget
	stdoutFmt  string // at most one stdout format, or ""
	cdxFile    string // CDX file path, or ""
	sarifFile  string // SARIF file path, or ""
	prettyOnly bool   // true when no stdout format → emit pretty output
}

// parseOutputFlags classifies each --output value.
func parseOutputFlags(args []string) (*outputConfig, error) {
	cfg := &outputConfig{}

	for _, arg := range args {
		switch strings.ToLower(arg) {
		case "json-cyclonedx":
			if cfg.stdoutFmt != "" {
				return nil, fmt.Errorf("cannot combine --output %s and --output %s: only one stdout format allowed", cfg.stdoutFmt, arg)
			}
			cfg.stdoutFmt = "json-cyclonedx"
			cfg.targets = append(cfg.targets, outputTarget{stdoutFmt: "json-cyclonedx", fileKind: "cdx"})

		case "json-sarif":
			if cfg.stdoutFmt != "" {
				return nil, fmt.Errorf("cannot combine --output %s and --output %s: only one stdout format allowed", cfg.stdoutFmt, arg)
			}
			cfg.stdoutFmt = "json-sarif"
			cfg.targets = append(cfg.targets, outputTarget{stdoutFmt: "json-sarif", fileKind: "sarif"})

		default:
			// File path — infer kind from extension.
			kind := inferFileKind(arg)
			if kind == "" {
				return nil, fmt.Errorf("cannot infer output format for %q: use .cdx.json for CycloneDX or .sarif for SARIF", arg)
			}
			switch kind {
			case "cdx":
				if cfg.cdxFile != "" {
					return nil, fmt.Errorf("duplicate CycloneDX file output: %q and %q", cfg.cdxFile, arg)
				}
				cfg.cdxFile = arg
			case "sarif":
				if cfg.sarifFile != "" {
					return nil, fmt.Errorf("duplicate SARIF file output: %q and %q", cfg.sarifFile, arg)
				}
				cfg.sarifFile = arg
			}
			cfg.targets = append(cfg.targets, outputTarget{filePath: arg, fileKind: kind})
		}
	}

	cfg.prettyOnly = cfg.stdoutFmt == ""
	return cfg, nil
}

// inferFileKind returns "cdx" or "sarif" based on file extension, or "" if unknown.
func inferFileKind(path string) string {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".cdx.json") || strings.HasSuffix(lower, ".cdx") {
		return "cdx"
	}
	if strings.HasSuffix(lower, ".sarif") || strings.HasSuffix(lower, ".sarif.json") {
		return "sarif"
	}
	// Also accept common BOM extensions.
	if strings.HasSuffix(lower, ".bom.json") || strings.HasSuffix(lower, ".sbom.json") {
		return "cdx"
	}
	return ""
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
  • A CycloneDX SBOM is written to .vulnetix/sbom.cdx.json
  • SAST SARIF report is written to .vulnetix/sast.sarif
  • Scan state is recorded in .vulnetix/memory.yaml
  • A summary or machine-readable JSON is printed to stdout

Output routing (--output, repeatable):
  json-cyclonedx         CycloneDX JSON to stdout
  json-sarif             SARIF JSON to stdout
  /path/file.cdx.json    CycloneDX to file, pretty output to stdout
  /path/file.sarif       SARIF to file, pretty output to stdout

Multiple --output flags can combine file outputs with pretty display.
Two stdout formats (json-cyclonedx + json-sarif) in one invocation is an error.

Examples:
  vulnetix scan                        # pretty output, auto-discover manifests
  vulnetix scan --path ./myproject
  vulnetix scan --depth 5
  vulnetix scan --exclude "test*"
  vulnetix scan -o json-cyclonedx      # emit CycloneDX JSON to stdout
  vulnetix scan -o json-sarif          # emit SARIF JSON to stdout
  vulnetix scan -o /tmp/out.cdx.json   # save CDX to file, pretty to stdout
  vulnetix scan -o /tmp/out.sarif      # save SARIF to file, pretty to stdout
  vulnetix scan -o /tmp/out.cdx.json -o /tmp/out.sarif  # save both, pretty to stdout
  vulnetix scan --no-progress          # suppress progress bar
  vulnetix scan --severity high        # exit 1 if any vuln is high or critical
  vulnetix scan --severity low         # exit 1 on any scored severity (low+)
  vulnetix scan --block-malware        # exit 1 on any known malicious package
  vulnetix scan --block-eol            # exit 1 if runtime is end-of-life
  vulnetix scan --block-unpinned       # exit 1 if any direct dep uses a version range
  vulnetix scan --exploits poc         # exit 1 if any vuln has a public exploit
  vulnetix scan --exploits active      # exit 1 if any vuln is actively exploited (CISA/EU KEV)
  vulnetix scan --version-lag 1        # exit 1 if using the very latest release of any dep
  vulnetix scan --cooldown 3           # exit 1 if any dep was published in the last 3 days
  vulnetix scan --block-malware --block-unpinned --version-lag 1 --cooldown 3 --severity high
  vulnetix scan --results-only         # silent when clean; show table only when findings exist
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

		// ── --list-default-rules: print built-in SAST rules and exit ──────
		listDefaultRules, _ := cmd.Flags().GetBool("list-default-rules")
		if listDefaultRules {
			return listBuiltinSASTRules()
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

		// Feature control flags.
		evaluateSAST, _ := cmd.Flags().GetBool("evaluate-sast")
		noSAST, _ := cmd.Flags().GetBool("no-sast")
		evaluateSCA, _ := cmd.Flags().GetBool("evaluate-sca")
		noSCA, _ := cmd.Flags().GetBool("no-sca")
		evaluateLicenses, _ := cmd.Flags().GetBool("evaluate-licenses")
		noLicenses, _ := cmd.Flags().GetBool("no-licenses")
		evaluateSecrets, _ := cmd.Flags().GetBool("evaluate-secrets")
		noSecrets, _ := cmd.Flags().GetBool("no-secrets")
		enableContainers, _ := cmd.Flags().GetBool("enable-containers")
		noContainers, _ := cmd.Flags().GetBool("no-containers")
		evaluateIAC, _ := cmd.Flags().GetBool("evaluate-iac")
		noIAC, _ := cmd.Flags().GetBool("no-iac")

		// Apply feature control logic:
		// If any --evaluate-X flag is set, disable everything not explicitly evaluated.
		// --no-X flags always disable regardless.
		anyEvaluate := evaluateSAST || evaluateSCA || evaluateLicenses || evaluateSecrets || enableContainers || evaluateIAC
		if anyEvaluate {
			noSAST = noSAST || !evaluateSAST
			noSCA = noSCA || !evaluateSCA
			noLicenses = noLicenses || !evaluateLicenses
			noSecrets = noSecrets || !evaluateSecrets
			noContainers = noContainers || !enableContainers
			noIAC = noIAC || !evaluateIAC
		}

		return runScanWithFeatures(cmd.Context(), cmd, noSAST, noSCA, noLicenses, noSecrets, noContainers, noIAC)

	},
}

// runScanWithFeatures executes the full scan pipeline with the given feature toggles.
// noSAST disables "sast"-kind static analysis rules, noSCA skips ordinary package
// manifests, noLicenses skips license evaluation, noSecrets skips secret-detection
// rules, noContainers skips Dockerfile/OCI manifests and rules, noIAC skips
// HCL/Nix manifests and IaC rules.
func runScanWithFeatures(ctx context.Context, cmd *cobra.Command, noSAST, noSCA, noLicenses, noSecrets, noContainers, noIAC bool) error {
	scanPath, _ := cmd.Flags().GetString("path")
	depth, _ := cmd.Flags().GetInt("depth")
	excludes, _ := cmd.Flags().GetStringArray("exclude")
	outputArgs, _ := cmd.Flags().GetStringArray("output")
	// Backward compat: if --format is set and --output is not, map it.
	if len(outputArgs) == 0 {
		if legacyFmt, _ := cmd.Flags().GetString("format"); legacyFmt != "" {
			outputArgs = []string{"json-cyclonedx"}
		}
	}
	outCfg, err := parseOutputFlags(outputArgs)
	if err != nil {
		return err
	}
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

	blockMalware, _ := cmd.Flags().GetBool("block-malware")
	blockEOL, _ := cmd.Flags().GetBool("block-eol")
	blockUnpinned, _ := cmd.Flags().GetBool("block-unpinned")
	exploitThreshold, _ := cmd.Flags().GetString("exploits")
	resultsOnly, _ := cmd.Flags().GetBool("results-only")
	versionLag, _ := cmd.Flags().GetInt("version-lag")
	cooldownDays, _ := cmd.Flags().GetInt("cooldown")

	// Normalise and validate the exploit threshold.
	if exploitThreshold != "" {
		exploitThreshold = strings.ToLower(strings.TrimSpace(exploitThreshold))
		validExploit := false
		for _, v := range scan.ValidExploitThresholds {
			if exploitThreshold == v {
				validExploit = true
				break
			}
		}
		if !validExploit {
			return fmt.Errorf("invalid --exploits %q: must be one of: %s",
				exploitThreshold, strings.Join(scan.ValidExploitThresholds, ", "))
		}
	}

	// SAST flags.
	disableDefaultRules, _ := cmd.Flags().GetBool("disable-default-rules")
	ruleArgs, _ := cmd.Flags().GetStringArray("rule")
	ruleRegistry, _ := cmd.Flags().GetString("rule-registry")
	ruleID, _ := cmd.Flags().GetString("rule-id")
	ruleID = strings.ToUpper(strings.TrimSpace(ruleID))
	if ruleID != "" {
		// Single-rule mode: skip SCA and license checks entirely.
		noSCA = true
		noLicenses = true
	}
	if ruleRegistry == "" {
		ruleRegistry = sast.DefaultRegistry
	}
	var ruleRefs []sast.RuleRef
	for _, arg := range ruleArgs {
		ref, err := sast.ParseRuleRef(arg)
		if err != nil {
			return err
		}
		ruleRefs = append(ruleRefs, ref)
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

	analytics.TrackScan("sbom", len(files))
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "No scannable files detected.")
		return nil
	}

	// ── 3. Display detected files ──────────────────────────────────────
	if !resultsOnly {
		fmt.Fprintln(os.Stderr, "Detected files:")
	}
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
			if !resultsOnly {
				fmt.Fprintf(os.Stderr, "  %-40s manifest    %-10s (%s) %s%s\n",
					f.RelPath, f.ManifestInfo.Ecosystem, f.ManifestInfo.Language, lockStr, supportedStr)
			}
		case scan.FileTypeSPDX:
			if !resultsOnly {
				fmt.Fprintf(os.Stderr, "  %-40s spdx        v%-9s\n", f.RelPath, f.SBOMVersion)
			}
		case scan.FileTypeCycloneDX:
			// Parse the CDX to check the producer.
			cdxBom, cdxErr := parseCDXForScan(f.Path)
			if cdxErr == nil && isVulnetixSCA(cdxBom) {
				if !resultsOnly {
					fmt.Fprintf(os.Stderr, "  %-40s %s\n", f.RelPath,
						display.Teal(t, "[skipped — produced by vulnetix-sca]"))
				}
				if vulnetixSCAVersion(cdxBom) == version {
					vulnetixSeedBOM = cdxBom
				}
				continue
			}
			if cdxErr == nil && cdxBom != nil {
				if !resultsOnly {
					fmt.Fprintf(os.Stderr, "  %-40s cyclonedx   v%-8s (%d comp, %d vulns)\n",
						f.RelPath, f.SBOMVersion, len(cdxBom.Components), len(cdxBom.Vulnerabilities))
				}
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

	// ── 4. Filter files by feature flags ──────────────────────────────
	supportedFiles = filterFilesByFeature(supportedFiles, noSCA, noContainers, noIAC)

	// ── 5. Collect host environment ─────────────────────────────────────
	sysInfo := gitctx.CollectSystemInfo()

	// ── 6. Run local scan ──────────────────────────────────────────────
	return runLocalScan(
		ctx,
		supportedFiles,
		scanPath,
		depth,
		excludes,
		outCfg,
		concurrency,
		noProgress,
		showPaths,
		noExploits,
		noRemediation,
		noLicenses,
		severityThreshold,
		blockMalware,
		blockEOL,
		blockUnpinned,
		exploitThreshold,
		resultsOnly,
		versionLag,
		cooldownDays,
		noSAST,
		noSecrets,
		noContainers,
		noIAC,
		disableDefaultRules,
		ruleRefs,
		ruleRegistry,
		ruleID,
		seedBOM,
		vulnetixSeedBOM,
		gitCtx,
		sysInfo,
	)
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
	depth int,
	excludes []string,
	outCfg *outputConfig,
	concurrency int,
	noProgress bool,
	showPaths bool,
	noExploits bool,
	noRemediation bool,
	noLicenses bool,
	severityThreshold string,
	blockMalware bool,
	blockEOL bool,
	blockUnpinned bool,
	exploitThreshold string,
	resultsOnly bool,
	versionLag int,
	cooldownDays int,
	noSASTRules bool,
	noSecrets bool,
	noContainers bool,
	noIAC bool,
	disableDefaultRules bool,
	ruleRefs []sast.RuleRef,
	ruleRegistry string,
	ruleID string,
	seedBOM *cdx.BOM,
	vulnetixSeedBOM *cdx.BOM,
	gitCtx *gitctx.GitContext,
	sysInfo *gitctx.SystemInfo,
) error {
	// Create a v1 VDB client for package search (not the upload/scan v2 client).
	client := newSearchClient()
	if !resultsOnly {
		fmt.Fprintf(os.Stderr, "\nAnalysing %d file(s)... parsing manifests locally.\n\n", len(files))
	}
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
			if !resultsOnly {
				fmt.Fprintf(os.Stderr, "  %-40s %d packages%s\n", f.RelPath, len(pkgs), formatScopeCounts(scopeCounts))
			}
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
		if !resultsOnly {
			fmt.Fprintf(os.Stderr, "  %-40s %d packages%s\n", f.RelPath, len(pkgs), scopeSummary)
		}
		localResults = append(localResults, cdx.LocalScanResult{File: f, Packages: pkgs})
		allPackages = append(allPackages, pkgs...)
	}

	if len(allPackages) == 0 {
		fmt.Fprintln(os.Stderr, "\nNo packages found to analyse.")
		// Still run license analysis and SAST even when no packages are found.
		localResults = []cdx.LocalScanResult{}
		allPackages = []scan.ScopedPackage{}
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

	// Populate dependency graph edges from locally installed packages.
	// This improves SBOM dependency tree accuracy and enables --paths for all ecosystems.
	scan.PopulateInstalledEdges(manifestGroups, rootPath)

	// Collect IDS rules.
	idsRules := scan.CollectIDSRules(enrichedVulns)

	// ── Update .vulnetix/memory.yaml ──────────────────────────────────────
	// Memory is loaded and reconciled BEFORE building the BOM so that VEX
	// entries for remediated / regressed findings can be included in the SBOM.
	vulnetixDir := filepath.Join(rootPath, ".vulnetix")
	mem, _ := memory.Load(vulnetixDir)
	if mem == nil {
		mem = &memory.Memory{Version: "1"}
	}

	var stateChanges []memory.StateChange

	// Write enriched findings to memory unless disabled.
	if !disableMemory && len(enrichedVulns) > 0 {
		// Build a map of source files per (CveID, PkgName) from all local results.
		sourceFileMap := map[string][]string{} // key: CveID::PkgName
		for _, r := range localResults {
			for _, v := range r.Vulns {
				k := v.CveID + "::" + v.PackageName
				sourceFileMap[k] = appendUnique(sourceFileMap[k], r.File.RelPath)
			}
		}

		findings := make([]memory.EnrichedFinding, 0, len(enrichedVulns))
		for _, ev := range enrichedVulns {
			ef := memory.EnrichedFinding{
				CveID:            ev.CveID,
				PackageName:      ev.PackageName,
				InstalledVersion: ev.PackageVer,
				Ecosystem:        ev.Ecosystem,
				MaxSeverity:      ev.MaxSeverity,
				AffectedRange:    ev.AffectedRange,
				IsMalicious:      ev.IsMalicious,
				Confirmed:        ev.Confirmed,
				InCisaKev:        ev.InCisaKev,
				InEuKev:          ev.InEuKev,
				PathCount:        ev.PathCount,
				CVSSScore:        ev.CVSSScore,
				CVSSSeverity:     ev.CVSSSeverity,
				EPSSScore:        ev.EPSSScore,
				EPSSPercentile:   ev.EPSSPercentile,
				EPSSSeverity:     ev.EPSSSeverity,
				CoalitionESS:     ev.CoalitionESS,
				CESSeverity:      ev.CESSeverity,
				SSVCDecision:     ev.SSVCDecision,
				SSVCSeverity:     ev.SSVCSeverity,
				ThreatExposure:   ev.ThreatExposure,
			}

			// Source files from manifest detection.
			k := ev.CveID + "::" + ev.PackageName
			ef.SourceFiles = sourceFileMap[k]
			if len(ef.SourceFiles) == 0 && ev.SourceFile != "" {
				ef.SourceFiles = []string{ev.SourceFile}
			}

			// Fix version from remediation.
			if ev.Remediation != nil {
				ef.FixVersion = ev.Remediation.FixVersion
				ef.Remediation = &memory.RemediationData{
					FixAvailability: ev.Remediation.FixAvailability,
					FixVersion:      ev.Remediation.FixVersion,
					Actions:         ev.Remediation.Actions,
				}
			}

			// Exploit intel.
			if ev.ExploitIntel != nil {
				ef.ExploitInfo = &memory.ExploitInfo{
					ExploitCount:    ev.ExploitIntel.ExploitCount,
					Sources:         ev.ExploitIntel.Sources,
					HasWeaponized:   ev.ExploitIntel.HasWeaponized,
					HighestMaturity: ev.ExploitIntel.HighestMaturity,
				}
			}

			// Compute introduced dependency paths when --paths was used.
			if showPaths {
				for _, mg := range manifestGroups {
					if mg.Graph != nil && !mg.Graph.IsDirect(ev.PackageName) {
						if chain := mg.Graph.FindPath(ev.PackageName); len(chain) > 1 {
							ef.IntroducedPaths = append(ef.IntroducedPaths, chain)
						}
					}
				}
			}

			findings = append(findings, ef)
		}
		mem.RecordEnrichedFindings(findings)

		// Reconcile: detect remediated and regressed findings.
		currentCVEs := make(map[string]bool, len(enrichedVulns))
		for _, ev := range enrichedVulns {
			currentCVEs[ev.CveID] = true
		}
		stateChanges = mem.ReconcileFindings(currentCVEs)
	} else if !disableMemory {
		// No vulns in current scan — reconcile all existing findings.
		stateChanges = mem.ReconcileFindings(map[string]bool{})
	}

	// Record scan summary.
	sbomPath := filepath.Join(vulnetixDir, "sbom.cdx.json")
	rec := buildScanRecord(localResults, allVulns, files, rootPath, gitCtx, sysInfo, sbomPath)

	// ── Write IDS rules if any ───────────────────────────────────────────
	rulesPath := ""
	if len(idsRules) > 0 {
		rulesPath = filepath.Join(vulnetixDir, "detection-rules.rules")
		if err := writeIDSRulesFile(rulesPath, idsRules); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: could not write IDS rules: %v\n", err)
			rulesPath = ""
		}
	}
	if rulesPath != "" {
		rec.IDSRulesPath = ".vulnetix/detection-rules.rules"
		rec.IDSRulesCount = len(idsRules)
	}

	// ── SAST analysis ────────────────────────────────────────────────────
	// Run SAST if at least one SAST sub-category is enabled.
	disableAllSAST := noSASTRules && noSecrets && noContainers && noIAC
	var sastReport *sast.SASTReport
	if !disableAllSAST {
		modules, merr := sast.LoadAllModules(sast.DefaultRulesFS, disableDefaultRules, ruleRefs, ruleRegistry, os.Stderr)
		if merr != nil {
			fmt.Fprintf(os.Stderr, "  warning: could not load SAST rules: %v\n", merr)
		}
		if len(modules) > 0 {
			modules = filterModulesByKind(modules, noSASTRules, noSecrets, noContainers, noIAC)
			modules = filterModulesByID(modules, ruleID)
			eng := sast.NewEngine(modules, rootPath)
			var eerr error
			sastReport, eerr = eng.Evaluate(sast.EvalOptions{MaxDepth: depth, Excludes: excludes})
			if eerr != nil {
				fmt.Fprintf(os.Stderr, "  warning: SAST evaluation failed: %v\n", eerr)
			}
		}
		if sastReport != nil {
			rec.SASTRulesLoaded = sastReport.RulesLoaded
			rec.SASTFindingCount = len(sastReport.Findings)

			sarifPath := filepath.Join(vulnetixDir, "sast.sarif")
			if !disableMemory {
				// Reconcile with previous SARIF for resolved findings.
				oldSARIF, _ := sast.LoadExistingSARIF(sarifPath)
				resolved := sast.ResolvedFingerprints(oldSARIF, sastReport.Findings)

				// Record SAST findings in memory.
				memFindings := make([]memory.SASTFindingRecord, 0, len(sastReport.Findings))
				for _, f := range sastReport.Findings {
					mf := memory.SASTFindingRecord{
						RuleID:      f.RuleID,
						Severity:    f.Severity,
						ArtifactURI: f.ArtifactURI,
						StartLine:   f.StartLine,
						Fingerprint: f.Fingerprint,
					}
					if f.Metadata != nil {
						mf.RuleName = f.Metadata.Name
					}
					memFindings = append(memFindings, mf)
				}
				mem.RecordSASTFindings(memFindings)
				for _, fp := range resolved {
					mem.MarkSASTFindingResolved(fp)
				}
			}
			// Write updated SARIF.
			sarifLog := sast.BuildSARIF(sastReport.Findings, sastReport.Rules, version)
			if werr := sast.WriteSARIF(sarifLog, sarifPath); werr != nil {
				fmt.Fprintf(os.Stderr, "  warning: could not write sast.sarif: %v\n", werr)
			} else {
				rec.SARIFPath = ".vulnetix/sast.sarif"
			}
		}
	}

	mem.RecordScan(rec)

	if err := memory.Save(vulnetixDir, mem); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: could not update memory.yaml: %v\n", err)
	}

	// ── Write .vulnetix/sbom.cdx.json ────────────────────────────────────
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

	// Inject VEX entries for remediated and regressed findings.
	for _, sc := range stateChanges {
		vexVuln := cdx.Vulnerability{
			BOMRef: sc.CveID,
			ID:     sc.CveID,
			Source: &cdx.Source{
				Name: "vulnetix-sca",
			},
		}
		switch sc.NewStatus {
		case "fixed":
			vexVuln.Analysis = &cdx.Analysis{
				State:         "resolved",
				Justification: "update",
				Detail:        sc.Comment,
			}
		case "under_investigation":
			vexVuln.Analysis = &cdx.Analysis{
				State:  "in_triage",
				Detail: sc.Comment,
			}
		}
		vexVuln.Properties = append(vexVuln.Properties, cdx.Property{
			Name:  "vulnetix:vex-auto",
			Value: "true",
		})
		if sc.Package != "" {
			vexVuln.Properties = append(vexVuln.Properties, cdx.Property{
				Name:  "vulnetix:package",
				Value: sc.Package,
			})
		}
		bom.Vulnerabilities = append(bom.Vulnerabilities, vexVuln)
	}

	// ── License analysis (unless --no-licenses) ────────────────────────────
	var licenseResult *license.AnalysisResult
	if !noLicenses {
		licensedPackages := license.DetectLicenses(allPackages, manifestGroups)
		licenseResult = license.Evaluate(licensedPackages, license.EvalConfig{Mode: "inclusive"})

		// Append license findings as CDX vulnerabilities.
		licenseVulns := license.FindingsToCDXVulnerabilities(licenseResult.Findings, licenseResult.Packages)
		bom.Vulnerabilities = append(bom.Vulnerabilities, licenseVulns...)

		// Populate license data on BOM components.
		licenseMap := make(map[string]string)
		for _, pkg := range licensedPackages {
			key := pkg.PackageName + "@" + pkg.PackageVersion
			if pkg.LicenseSpdxID != "UNKNOWN" {
				licenseMap[key] = pkg.LicenseSpdxID
			}
		}
		cdx.PopulateLicenses(bom, licenseMap)

		// Write license findings to memory.
		if !disableMemory && mem != nil && len(licenseResult.Findings) > 0 {
			for _, f := range licenseResult.Findings {
				mem.Findings[f.ID] = memory.FindingRecord{
					Package:         f.Package.PackageName,
					Ecosystem:       f.Package.Ecosystem,
					Severity:        f.Severity,
					Status:          "affected",
					Source:           license.CDXSourceName,
					Versions:         &memory.VersionInfo{Current: f.Package.PackageVersion},
					SourceFiles:     []string{f.Package.SourceFile},
					IntroducedPaths: f.IntroducedPaths,
					PathCount:       f.PathCount,
				}
			}
			if err := memory.Save(vulnetixDir, mem); err != nil {
				fmt.Fprintf(os.Stderr, "  warning: could not update memory.yaml with license findings: %v\n", err)
			}
		}
	}

	// Populate dependency tree from manifest group edges.
	compRefs := cdx.ExportCompRefs(bom)
	bom.Dependencies = cdx.BuildDependencies(manifestGroups, compRefs)

	if err := writeBOMToFile(bom, sbomPath); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: could not write BOM: %v\n", err)
	}

	// ── Quality gate evaluation ───────────────────────────────────────────
	// Evaluated after writing artefacts so that the SBOM and memory.yaml are
	// always written regardless of exit code, giving CI pipelines access to
	// the full findings even when the build is broken.
	var breaches []GateBreach

	// Gate 1: malware
	if blockMalware {
		var malwareVulns []scan.EnrichedVuln
		for _, ev := range enrichedVulns {
			if ev.IsMalicious {
				malwareVulns = append(malwareVulns, ev)
			}
		}
		if len(malwareVulns) > 0 {
			breaches = append(breaches, GateBreach{
				Gate:  "malware",
				Count: len(malwareVulns),
				Message: fmt.Sprintf("--block-malware: %d malicious %s detected",
					len(malwareVulns), pluralise("package", len(malwareVulns))),
			})
		}
	}

	// Gate 2: exploits
	if exploitThreshold != "" {
		var exploitVulns []scan.EnrichedVuln
		for _, ev := range enrichedVulns {
			if scan.ExploitMeetsThreshold(ev, exploitThreshold) {
				exploitVulns = append(exploitVulns, ev)
			}
		}
		if len(exploitVulns) > 0 {
			breaches = append(breaches, GateBreach{
				Gate:  "exploits",
				Count: len(exploitVulns),
				Message: fmt.Sprintf("--exploits %s: %d %s",
					exploitThreshold, len(exploitVulns), pluralise("vulnerability", len(exploitVulns))),
			})
		}
	}

	// Gate 3: severity
	if severityThreshold != "" {
		var severityVulns []scan.EnrichedVuln
		for _, ev := range enrichedVulns {
			if scan.SeverityMeetsThreshold(ev.MaxSeverity, severityThreshold) {
				severityVulns = append(severityVulns, ev)
			}
		}
		if len(severityVulns) > 0 {
			breaches = append(breaches, GateBreach{
				Gate:  "severity",
				Count: len(severityVulns),
				Message: fmt.Sprintf("--severity %s: %d %s",
					severityThreshold, len(severityVulns), pluralise("vulnerability", len(severityVulns))),
			})
		}
	}

	// Gate 4: EOL — best-effort runtime version pin detection + VDB EOL API.
	if blockEOL {
		eolClient := newSearchClient()
		pins := scan.DetectRuntimeVersionPins(rootPath)
		var eolViolations []string
		for _, pin := range pins {
			resp, err := eolClient.EOLRelease(pin.Product, pin.Release)
			if err != nil {
				continue // silently skip: unknown product / network error
			}
			if resp.Release.IsEol {
				eolViolations = append(eolViolations, fmt.Sprintf("%s %s (%s)", pin.Product, pin.RawVersion, pin.SourceFile))
			}
		}
		if len(eolViolations) > 0 {
			breaches = append(breaches, GateBreach{
				Gate:  "eol",
				Count: len(eolViolations),
				Message: fmt.Sprintf("--block-eol: %d end-of-life %s: %s",
					len(eolViolations), pluralise("runtime", len(eolViolations)),
					strings.Join(eolViolations, ", ")),
			})
		}

		// Package-level EOL — silently skips packages not yet in VDB EOL database.
		type pkgEOLKey struct{ ecosystem, name, version string }
		seen := map[pkgEOLKey]bool{}
		var pkgItems []pkgEOLKey
		for _, p := range allPackages {
			key := pkgEOLKey{p.Ecosystem, p.Name, p.Version}
			if seen[key] || p.Version == "" {
				continue
			}
			seen[key] = true
			pkgItems = append(pkgItems, key)
		}
		eolPkgResults := make([]string, len(pkgItems))
		eolPkgSem := make(chan struct{}, concurrency)
		var eolPkgWg sync.WaitGroup
		for idx, item := range pkgItems {
			eolPkgWg.Add(1)
			go func(i int, it pkgEOLKey) {
				defer eolPkgWg.Done()
				eolPkgSem <- struct{}{}
				defer func() { <-eolPkgSem }()
				resp, err := eolClient.EOLPackageVersion(it.ecosystem, it.name, it.version)
				if err != nil || resp == nil || !resp.Release.IsEol {
					return
				}
				eolPkgResults[i] = fmt.Sprintf("%s@%s (%s)", it.name, it.version, it.ecosystem)
			}(idx, item)
		}
		eolPkgWg.Wait()
		var eolPkgList []string
		for _, v := range eolPkgResults {
			if v != "" {
				eolPkgList = append(eolPkgList, v)
			}
		}
		if len(eolPkgList) > 0 {
			breaches = append(breaches, GateBreach{
				Gate:  "eol",
				Count: len(eolPkgList),
				Message: fmt.Sprintf("--block-eol: %d end-of-life %s: %s",
					len(eolPkgList), pluralise("package", len(eolPkgList)),
					strings.Join(eolPkgList, ", ")),
			})
		}
	}

	// Gate 5: unpinned direct dependencies
	if blockUnpinned {
		seenUnpinned := map[string]bool{}
		var unpinnedPkgs []scan.ScopedPackage
		for _, p := range allPackages {
			if !p.IsDirect {
				continue
			}
			if scan.IsVersionSpecPinned(p.VersionSpec) {
				continue
			}
			key := p.Name + ":" + p.Ecosystem
			if !seenUnpinned[key] {
				seenUnpinned[key] = true
				unpinnedPkgs = append(unpinnedPkgs, p)
			}
		}
		if len(unpinnedPkgs) > 0 {
			breaches = append(breaches, GateBreach{
				Gate:  "unpinned",
				Count: len(unpinnedPkgs),
				Message: fmt.Sprintf("--block-unpinned: %d %s with unpinned version spec",
					len(unpinnedPkgs), pluralise("dependency", len(unpinnedPkgs))),
			})
		}
	}

	// Gates 6 & 7: version-lag and cooldown — share a single batch version fetch.
	if versionLag > 0 || cooldownDays > 0 {
		type pkgVersionData struct {
			versions []vdb.VersionRecord
		}
		versionDataMap := make(map[string]pkgVersionData)

		type pkgKey struct{ Name, Ecosystem string }
		uniquePkgKeys := map[pkgKey]bool{}
		for _, p := range allPackages {
			uniquePkgKeys[pkgKey{p.Name, p.Ecosystem}] = true
		}

		var vdMu sync.Mutex
		var vdWg sync.WaitGroup
		vdSem := make(chan struct{}, concurrency)
		for k := range uniquePkgKeys {
			vdWg.Add(1)
			vdSem <- struct{}{}
			go func(name, ecosystem string) {
				defer vdWg.Done()
				defer func() { <-vdSem }()
				resp, err := client.GetProductVersions(name, 200, 0)
				if err != nil {
					return
				}
				vdMu.Lock()
				versionDataMap[name+"::"+ecosystem] = pkgVersionData{versions: resp.Versions}
				vdMu.Unlock()
			}(k.Name, k.Ecosystem)
		}
		vdWg.Wait()

		// Gate 6: version-lag
		if versionLag > 0 {
			seenLag := map[string]bool{}
			var lagViolations []string
			for _, p := range allPackages {
				key := p.Name + "::" + p.Ecosystem
				if seenLag[key] {
					continue
				}
				seenLag[key] = true
				data, ok := versionDataMap[key]
				if !ok || len(data.versions) == 0 {
					continue
				}
				sorted := sortVersionsDesc(data.versions)
				installedParsed, err := update.ParseVersion(strings.TrimPrefix(p.Version, "v"))
				if err != nil {
					continue
				}
				for rank, rec := range sorted {
					v, err := update.ParseVersion(strings.TrimPrefix(rec.Version, "v"))
					if err != nil {
						continue
					}
					if v.Compare(installedParsed) == 0 {
						if rank < versionLag {
							lagViolations = append(lagViolations,
								fmt.Sprintf("%s@%s (rank %d of %d)", p.Name, p.Version, rank+1, len(sorted)))
						}
						break
					}
				}
			}
			if len(lagViolations) > 0 {
				breaches = append(breaches, GateBreach{
					Gate:  "version-lag",
					Count: len(lagViolations),
					Message: fmt.Sprintf("--version-lag %d: %d %s within the %d most recent %s: %s",
						versionLag, len(lagViolations), pluralise("dependency", len(lagViolations)),
						versionLag, pluralise("release", versionLag),
						strings.Join(lagViolations, ", ")),
				})
			}
		}

		// Gate 7: cooldown
		if cooldownDays > 0 {
			cutoff := time.Now().UTC().AddDate(0, 0, -cooldownDays)
			seenCooldown := map[string]bool{}
			var cooldownViolations []string
			for _, p := range allPackages {
				key := p.Name + "::" + p.Ecosystem
				if seenCooldown[key] {
					continue
				}
				seenCooldown[key] = true
				data, ok := versionDataMap[key]
				if !ok {
					continue
				}
				for _, rec := range data.versions {
					if strings.TrimPrefix(rec.Version, "v") != strings.TrimPrefix(p.Version, "v") {
						continue
					}
					t := extractPublishDate(rec)
					if t != nil && t.After(cutoff) {
						cooldownViolations = append(cooldownViolations,
							fmt.Sprintf("%s@%s (published %s)", p.Name, p.Version, t.Format("2006-01-02")))
					}
					break
				}
			}
			if len(cooldownViolations) > 0 {
				breaches = append(breaches, GateBreach{
					Gate:  "cooldown",
					Count: len(cooldownViolations),
					Message: fmt.Sprintf("--cooldown %d: %d %s published within last %d %s: %s",
						cooldownDays, len(cooldownViolations), pluralise("dependency", len(cooldownViolations)),
						cooldownDays, pluralise("day", cooldownDays),
						strings.Join(cooldownViolations, ", ")),
				})
			}
		}
	}

	// ── SAST quality gate ─────────────────────────────────────────────────
	if severityThreshold != "" && sastReport != nil {
		var n int
		for _, f := range sastReport.Findings {
			if scan.SeverityMeetsThreshold(f.Severity, severityThreshold) {
				n++
			}
		}
		if n > 0 {
			breaches = append(breaches, GateBreach{
				Gate:  "sast-severity",
				Count: n,
				Message: fmt.Sprintf("--severity %s: %d SAST %s",
					severityThreshold, n, pluralise("finding", n)),
			})
		}
	}

	// ── Output ────────────────────────────────────────────────────────────

	// Write any requested file outputs.
	if outCfg.cdxFile != "" {
		outBOM := cdx.BuildFromLocalScan(localResults, "1.7", scanCtx, seedBOM)
		if err := writeBOMToFile(outBOM, outCfg.cdxFile); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: could not write CDX to %s: %v\n", outCfg.cdxFile, err)
		}
	}
	if outCfg.sarifFile != "" && sastReport != nil {
		sarifLog := sast.BuildSARIF(sastReport.Findings, sastReport.Rules, version)
		if err := sast.WriteSARIF(sarifLog, outCfg.sarifFile); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: could not write SARIF to %s: %v\n", outCfg.sarifFile, err)
		}
	}

	// Stdout format: emit machine-readable JSON, no pretty output.
	if outCfg.stdoutFmt == "json-cyclonedx" {
		outBOM := cdx.BuildFromLocalScan(localResults, "1.7", scanCtx, seedBOM)
		if err := outBOM.WriteJSON(os.Stdout); err != nil {
			return err
		}
		if len(breaches) > 0 {
			return &MultiPolicyBreachError{Breaches: breaches}
		}
		return nil
	}
	if outCfg.stdoutFmt == "json-sarif" {
		sarifLog := sast.BuildSARIF(nil, nil, version)
		if sastReport != nil {
			sarifLog = sast.BuildSARIF(sastReport.Findings, sastReport.Rules, version)
		}
		data, merr := json.MarshalIndent(sarifLog, "", "  ")
		if merr != nil {
			return fmt.Errorf("marshal sarif: %w", merr)
		}
		os.Stdout.Write(data)
		fmt.Fprintln(os.Stdout)
		if len(breaches) > 0 {
			return &MultiPolicyBreachError{Breaches: breaches}
		}
		return nil
	}

	// Pretty output (default, or when only file outputs were requested).
	printPrettyScanSummary(enrichedVulns, manifestGroups, allPackages, showPaths, noExploits, noRemediation, sbomPath, vulnetixDir, rulesPath, resultsOnly)
	if licenseResult != nil && len(licenseResult.Findings) > 0 {
		printPrettyLicenseSummary(licenseResult, sbomPath, vulnetixDir)
	}
	sast.PrintPrettySummary(sastReport, resultsOnly)

	if len(breaches) > 0 {
		fmt.Fprintln(os.Stderr)
		for _, b := range breaches {
			fmt.Fprintf(os.Stderr, "  ✗ %s\n", b.Message)
		}
		return &MultiPolicyBreachError{Breaches: breaches}
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
	resultsOnly bool,
) {
	// --results-only: stay silent when there are no findings.
	if resultsOnly && len(enrichedVulns) == 0 {
		return
	}

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
	sevColor := func(s string) string { return display.SeverityText(t, strings.ToLower(s)) }
	cols := []display.Column{
		{Header: "File", MinWidth: 20, MaxWidth: 50, Color: func(s string) string {
			if strings.TrimSpace(s) == "" {
				return s
			}
			return display.Teal(t, s)
		}},
		{Header: "Vuln ID", MinWidth: 16, MaxWidth: 28},
		{Header: "Package", MinWidth: 14, MaxWidth: 36},
		{Header: "Mal", MinWidth: 3, MaxWidth: 3, Color: func(s string) string {
			if strings.TrimSpace(s) == "" {
				return s
			}
			return display.ErrorStyle(t, s)
		}},
		{Header: "MaxSev", MinWidth: 6, MaxWidth: 10, Color: sevColor},
		{Header: "CVSS", MinWidth: 4, MaxWidth: 6, Align: display.AlignRight},
		{Header: "CVSSSev", MinWidth: 4, MaxWidth: 8, Color: sevColor},
		{Header: "EPSS", MinWidth: 4, MaxWidth: 10, Align: display.AlignRight},
		{Header: "EPSSSev", MinWidth: 4, MaxWidth: 8, Color: sevColor},
		{Header: "SSVC", MinWidth: 4, MaxWidth: 8},
		{Header: "SSVCSev", MinWidth: 4, MaxWidth: 8, Color: sevColor},
		{Header: "CESS", MinWidth: 4, MaxWidth: 8, Align: display.AlignRight},
		{Header: "CESSev", MinWidth: 4, MaxWidth: 8, Color: sevColor},
		{Header: "Expl", MinWidth: 4, MaxWidth: 5, Align: display.AlignRight, Color: func(s string) string {
			if strings.TrimSpace(s) == "" || s == "0" {
				return display.Muted(t, s)
			}
			return display.Accent(t, s)
		}},
		{Header: "Fix", MinWidth: 3, MaxWidth: 20, Color: func(s string) string {
			switch strings.ToLower(strings.TrimSpace(s)) {
			case "available":
				return display.Success(t, s)
			case "partial":
				return display.Accent(t, s)
			case "no fix":
				return display.ErrorStyle(t, s)
			default:
				return s
			}
		}},
		{Header: "Match", MinWidth: 5, MaxWidth: 14},
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
			row := make([]string, 16)
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
				vulnID += " [CISA]"
			}
			if v.InEuKev {
				vulnID += " [EU]"
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

			matchMethod := v.MatchMethod
			if matchMethod == "" {
				matchMethod = "name"
			}

			allRows = append(allRows, []string{
				fileCell, vulnID, pkg, mal, maxSev,
				cvss, cvssSev, epss, epssSev,
				ssvc, ssvcSev, cess, cesSev, expl, fix, matchMethod,
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
		if !noExploits && !resultsOnly {
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
		if !noRemediation && !resultsOnly {
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
		if rl.DayLimit == 0 && rl.Remaining < 0 {
			fmt.Fprintf(os.Stderr, "  Rate limit: unlimited")
		} else {
			fmt.Fprintf(os.Stderr, "  Rate limit: %d/%d req/day remaining (resets %s)",
				rl.Remaining, rl.DayLimit, humanReset(rl.Reset))
		}
		if rl.Plan != "" {
			label := rl.Plan
			if rl.SoftLimits {
				label += ", soft limits"
			}
			fmt.Fprintf(os.Stderr, " [%s]", label)
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

// humanReset formats a rate-limit reset value into "in <duration>".
// The value may be a Unix epoch timestamp (>1_000_000_000) or relative seconds.
func humanReset(val int) string {
	if val <= 0 {
		return "now"
	}
	secs := val
	if val > 1_000_000_000 {
		secs = val - int(time.Now().Unix())
		if secs <= 0 {
			return "now"
		}
	}
	return "in " + formatDuration(secs)
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

// listBuiltinSASTRules loads default embedded rules, extracts metadata, and prints
// a table of built-in SAST rules. Used for --list-default-rules.
func listBuiltinSASTRules() error {
	modules, err := sast.LoadAllModules(sast.DefaultRulesFS, false, nil, "", os.Stderr)
	if err != nil {
		return fmt.Errorf("load default rules: %w", err)
	}
	if len(modules) == 0 {
		fmt.Fprintln(os.Stdout, "No built-in SAST rules found.")
		return nil
	}

	eng := sast.NewEngine(modules, ".")
	rules, err := eng.ListRules()
	if err != nil {
		return fmt.Errorf("list rules: %w", err)
	}
	if len(rules) == 0 {
		fmt.Fprintln(os.Stdout, "No built-in SAST rules found.")
		return nil
	}

	t := display.NewTerminal()
	cols := []display.Column{
		{Header: "ID", MinWidth: 12, MaxWidth: 16},
		{Header: "Severity", MinWidth: 8, MaxWidth: 10, Color: func(s string) string {
			return display.SeverityText(t, strings.ToLower(s))
		}},
		{Header: "Languages", MinWidth: 10, MaxWidth: 20},
		{Header: "Name", MinWidth: 20, MaxWidth: 50},
	}
	rows := make([][]string, 0, len(rules))
	for _, r := range rules {
		rows = append(rows, []string{
			r.ID,
			r.Severity,
			strings.Join(r.Languages, ", "),
			r.Name,
		})
	}
	fmt.Fprintln(os.Stdout)
	fmt.Fprint(os.Stdout, display.Table(t, cols, rows))
	fmt.Fprintf(os.Stdout, "\n%d built-in rules\n", len(rules))
	return nil
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
// appendUnique appends s to slice only if not already present.
func appendUnique(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}

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

// addScanFlags registers the common scan flags on cmd. Used by scan and all
// specialized scan subcommands (sca, sast, secrets, containers, iac).
func addScanFlags(cmd *cobra.Command) {
	cmd.Flags().String("path", ".", "Directory to scan")
	cmd.Flags().Int("depth", 3, "Max recursion depth")
	cmd.Flags().StringArray("exclude", nil, "Exclude paths matching glob (repeatable)")
	cmd.Flags().StringArrayP("output", "o", nil,
		"Output target (repeatable): json-cyclonedx or json-sarif for stdout; file path (.cdx.json, .sarif) to write to file")
	cmd.Flags().StringP("format", "f", "", "Deprecated: use --output instead")
	cmd.Flags().Int("concurrency", 5, "Max concurrent VDB queries")
	cmd.Flags().Bool("no-progress", false, "Suppress progress bar")
	cmd.Flags().Bool("paths", false, "Show full transitive dependency paths (npm, Python, Rust, Ruby, PHP, Go)")
	cmd.Flags().Bool("no-exploits", false, "Suppress detailed exploit intelligence section")
	cmd.Flags().Bool("no-remediation", false, "Suppress detailed remediation section")
	cmd.Flags().String("severity", "", "Exit with code 1 if any vulnerability meets or exceeds this severity (low, medium, high, critical). Severity is coerced from all available scoring sources (CVSS, EPSS, Coalition ESS, SSVC).")
	cmd.Flags().Bool("block-malware", false, "Exit with code 1 when any dependency is a known malicious package.")
	cmd.Flags().Bool("block-eol", false, "Exit with code 1 when a runtime or package dependency is end-of-life. Runtimes: Go, Node.js, Python, Ruby. Package-level checks activate when VDB has EOL data (404s are silently skipped).")
	cmd.Flags().Bool("block-unpinned", false, "Exit with code 1 when any direct dependency uses a version range (^, ~, >=) instead of an exact pin.")
	cmd.Flags().String("exploits", "", "Exit with code 1 when exploit maturity reaches the threshold: poc (any public exploit), active (CISA/EU KEV / actively exploited), weaponized (in-the-wild only).")
	cmd.Flags().Bool("results-only", false, "Only output when findings exist; completely silent when the scan is clean.")
	cmd.Flags().Int("version-lag", 0, "Exit with code 1 when any dependency is within the N most recently published versions of that package (0 = disabled).")
	cmd.Flags().Int("cooldown", 0, "Exit with code 1 when any dependency version was published within the last N days (0 = disabled, best-effort).")
	cmd.Flags().Bool("dry-run", false, "Detect files and parse packages locally, check memory, then exit — zero API calls")
	_ = cmd.Flags().MarkDeprecated("format", "use --output instead")
	_ = cmd.RegisterFlagCompletionFunc("exploits", cobra.FixedCompletions(
		scan.ValidExploitThresholds, cobra.ShellCompDirectiveNoFileComp))
	_ = cmd.RegisterFlagCompletionFunc("output", cobra.FixedCompletions(
		[]string{"json-cyclonedx", "json-sarif"}, cobra.ShellCompDirectiveDefault))
	_ = cmd.RegisterFlagCompletionFunc("severity", cobra.FixedCompletions(
		[]string{"low", "medium", "high", "critical"}, cobra.ShellCompDirectiveNoFileComp))
	_ = cmd.MarkFlagDirname("path")
}

// addSASTFlags registers SAST-specific flags on cmd.
func addSASTFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("disable-default-rules", false, "Skip built-in default SAST rules")
	cmd.Flags().Bool("list-default-rules", false, "Print built-in SAST rules and exit")
	cmd.Flags().StringArrayP("rule", "R", nil,
		"External SAST rule repo in org/repo format (repeatable); fetched from GitHub or --rule-registry")
	cmd.Flags().String("rule-registry", "",
		"Override default registry (https://github.com) for all --rule repos")
	cmd.Flags().String("rule-id", "",
		"Run only the single SAST rule with this ID (e.g. VNX-GQL-004); skips SCA and license checks")
}

// filterFilesByFeature removes detected files excluded by the active feature flags.
// noSCA removes ordinary package manifests; noContainers removes docker/OCI
// manifests; noIAC removes HCL and Nix manifests.
func filterFilesByFeature(files []scan.DetectedFile, noSCA, noContainers, noIAC bool) []scan.DetectedFile {
	if !noSCA && !noContainers && !noIAC {
		return files
	}
	filtered := make([]scan.DetectedFile, 0, len(files))
	for _, f := range files {
		if f.ManifestInfo == nil {
			// CDX / SPDX files — always include.
			filtered = append(filtered, f)
			continue
		}
		lang := f.ManifestInfo.Language
		isContainer := lang == "docker"
		isIAC := lang == "hcl" || lang == "nix"
		isSCA := !isContainer && !isIAC
		if isContainer && noContainers {
			continue
		}
		if isIAC && noIAC {
			continue
		}
		if isSCA && noSCA {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered
}

// filterModulesByKind removes Rego modules whose declared kind does not match
// the enabled feature flags. noSASTRules filters out "sast"-kind rules,
// noSecrets filters "secrets"-kind, noContainers filters "oci"-kind, noIAC
// filters "iac"-kind. Modules without a "kind" field default to "sast".
func filterModulesByKind(modules map[string]string, noSASTRules, noSecrets, noContainers, noIAC bool) map[string]string {
	if !noSASTRules && !noSecrets && !noContainers && !noIAC {
		return modules
	}
	filtered := make(map[string]string, len(modules))
	for name, src := range modules {
		kind := extractRegoKind(src)
		if kind == "sast" && noSASTRules {
			continue
		}
		if kind == "secrets" && noSecrets {
			continue
		}
		if kind == "oci" && noContainers {
			continue
		}
		if kind == "iac" && noIAC {
			continue
		}
		filtered[name] = src
	}
	return filtered
}

// filterModulesByID retains only the Rego module whose metadata "id" field
// matches ruleID (case-insensitive). Returns the original map unchanged when
// ruleID is empty.
func filterModulesByID(modules map[string]string, ruleID string) map[string]string {
	if ruleID == "" {
		return modules
	}
	target := strings.ToUpper(strings.TrimSpace(ruleID))
	filtered := make(map[string]string, 1)
	for name, src := range modules {
		if strings.ToUpper(extractRegoID(src)) == target {
			filtered[name] = src
			break
		}
	}
	return filtered
}

// extractRegoID returns the value of the "id" field from a Rego module's
// metadata block. Returns "" when no id is declared.
func extractRegoID(src string) string {
	i := strings.Index(src, `"id"`)
	if i < 0 {
		return ""
	}
	rest := src[i+4:]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	rest = rest[j+1:]
	k := strings.Index(rest, `"`)
	if k < 0 {
		return ""
	}
	return rest[:k]
}

// extractRegoKind returns the value of the "kind" field from a Rego module's
// metadata block. Returns "sast" when no kind is declared.
func extractRegoKind(src string) string {
	i := strings.Index(src, `"kind"`)
	if i < 0 {
		return "sast"
	}
	rest := src[i+6:]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return "sast"
	}
	rest = rest[j+1:]
	k := strings.Index(rest, `"`)
	if k < 0 {
		return "sast"
	}
	return rest[:k]
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.AddCommand(scanStatusCmd)

	addScanFlags(scanCmd)
	addSASTFlags(scanCmd)

	// Feature control flags (scan command only — specialized commands hard-code these)
	scanCmd.Flags().Bool("evaluate-sast", false, "Enable SAST analysis")
	scanCmd.Flags().Bool("no-sast", false, "Skip SAST analysis")
	scanCmd.Flags().Bool("evaluate-sca", false, "Enable SCA (Software Composition Analysis)")
	scanCmd.Flags().Bool("no-sca", false, "Skip SCA (Software Composition Analysis)")
	scanCmd.Flags().Bool("evaluate-licenses", false, "Enable license analysis")
	scanCmd.Flags().Bool("no-licenses", false, "Skip license analysis during scan")
	scanCmd.Flags().Bool("evaluate-secrets", false, "Enable secret detection via SAST rules")
	scanCmd.Flags().Bool("no-secrets", false, "Skip secret detection via SAST rules")
	scanCmd.Flags().Bool("enable-containers", false, "Enable container file detection")
	scanCmd.Flags().Bool("no-containers", false, "Skip container file detection")
	scanCmd.Flags().Bool("evaluate-iac", false, "Enable Infrastructure as Code detection")
	scanCmd.Flags().Bool("no-iac", false, "Skip Infrastructure as Code detection")

	// --from-memory and --fresh-* flags (scan command only)
	scanCmd.Flags().Bool("from-memory", false, "Reconstruct scan pretty output from .vulnetix/sbom.cdx.json without API calls")
	scanCmd.Flags().Bool("fresh-exploits", false, "With --from-memory: fetch latest exploit intel from API")
	scanCmd.Flags().Bool("fresh-advisories", false, "With --from-memory: fetch latest remediation plans from API")
	scanCmd.Flags().Bool("fresh-vulns", false, "With --from-memory: re-fetch affected version checks and latest scoring from API")

	// scan status flags
	scanStatusCmd.Flags().Bool("poll", false, "Poll until complete")
	scanStatusCmd.Flags().Int("poll-interval", 5, "Polling interval in seconds")
	scanStatusCmd.Flags().StringP("output", "o", "pretty", "Output format (json, pretty)")
	_ = scanStatusCmd.RegisterFlagCompletionFunc("output", cobra.FixedCompletions(
		[]string{"json", "pretty"}, cobra.ShellCompDirectiveNoFileComp))
}

// Ensure tui package is imported (used indirectly for color constants via display).
var _ = tui.ColorAccent

// sortVersionsDesc returns a copy of records sorted newest-first using semver comparison.
// Records whose version cannot be parsed are placed after all parseable ones.
func sortVersionsDesc(records []vdb.VersionRecord) []vdb.VersionRecord {
	out := make([]vdb.VersionRecord, len(records))
	copy(out, records)
	sort.SliceStable(out, func(i, j int) bool {
		vi, errI := update.ParseVersion(strings.TrimPrefix(out[i].Version, "v"))
		vj, errJ := update.ParseVersion(strings.TrimPrefix(out[j].Version, "v"))
		if errI != nil && errJ != nil {
			return out[i].Version > out[j].Version // fallback: lexicographic desc
		}
		if errI != nil {
			return false // unparseable goes last
		}
		if errJ != nil {
			return true
		}
		return vi.IsNewerThan(vj)
	})
	return out
}

// extractPublishDate probes common metadata keys in a VersionRecord's sources for
// a publication date. Returns nil when no parseable date is found (best-effort).
func extractPublishDate(rec vdb.VersionRecord) *time.Time {
	candidates := []string{"publishedAt", "published_at", "date", "createdAt", "created_at"}
	for _, src := range rec.Sources {
		for _, key := range candidates {
			val, ok := src.Metadata[key]
			if !ok {
				continue
			}
			s, ok := val.(string)
			if !ok || s == "" {
				continue
			}
			// Try RFC3339, then date-only.
			for _, layout := range []string{time.RFC3339, "2006-01-02"} {
				if t, err := time.Parse(layout, s); err == nil {
					t = t.UTC()
					return &t
				}
			}
		}
	}
	return nil
}
