package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/analytics"
	"github.com/vulnetix/cli/v3/internal/cdx"
	"github.com/vulnetix/cli/v3/internal/display"
	autofix "github.com/vulnetix/cli/v3/internal/fix"
	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/internal/license"
	"github.com/vulnetix/cli/v3/internal/memory"
	"github.com/vulnetix/cli/v3/internal/sast"
	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/internal/triage"
	"github.com/vulnetix/cli/v3/internal/tui"
	"github.com/vulnetix/cli/v3/internal/update"
	"github.com/vulnetix/cli/v3/pkg/auth"
	"github.com/vulnetix/cli/v3/pkg/cache"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// Package-level display toggles populated from flags before any scan runs.
// Kept here (not threaded through the many scan helpers) because they only
// affect how detection and table output is rendered, not control flow.
var (
	showDetectedFiles bool
	showAllManifests  bool
)

// SeverityBreachError is returned when --severity threshold is breached.
// It signals main() to exit with code 1 without printing a redundant error message.
type SeverityBreachError struct {
	threshold string
	count     int
}

func (e *SeverityBreachError) Error() string {
	return fmt.Sprintf("severity threshold %q breached: %s",
		e.threshold, pluralise("vulnerability", e.count))
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

func applyScanDisplayFlags(cmd *cobra.Command) {
	showDetectedFiles, _ = cmd.Flags().GetBool("show-detected")
	showAllManifests, _ = cmd.Flags().GetBool("show-all-manifests")
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
  vulnetix scan --no-progress          # suppress progress indicators
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
		printBanner(cmd)
		initDisplayContext(cmd, display.ModeText)
		applyScanDisplayFlags(cmd)
		// Credentials are optional — community fallback is used when absent.
		return resolveVDBCredentials(false)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// ── --dry-run path ──────────────────────────────────────────────────
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		scaAutofix, _ := cmd.Flags().GetBool("sca-autofix")
		if dryRun && !scaAutofix {
			for _, freshFlag := range []string{"fresh-exploits", "fresh-advisories", "fresh-vulns"} {
				if v, _ := cmd.Flags().GetBool(freshFlag); v {
					return fmt.Errorf("--%s cannot be used with --dry-run (dry run makes no API calls)", freshFlag)
				}
			}
			scanPath, _ := cmd.Flags().GetString("path")
			depth, _ := cmd.Flags().GetInt("depth")
			excludes, _ := cmd.Flags().GetStringArray("exclude")
			showPaths, _ := cmd.Flags().GetBool("show-introduced-paths")
			if !showPaths {
				// Deprecated alias for backward compatibility.
				showPaths, _ = cmd.Flags().GetBool("paths")
			}
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

		scanErr := runScanWithFeatures(cmd.Context(), cmd, noSAST, noSCA, noLicenses, noSecrets, noContainers, noIAC)

		// Capture AI coding-agent / SDK / model inventory alongside the scan.
		// Best-effort and authenticated-only; never changes the scan's exit code.
		if noAibom, _ := cmd.Flags().GetBool("no-aibom"); !noAibom {
			scanPath, _ := cmd.Flags().GetString("path")
			if scanPath == "" {
				scanPath = "."
			}
			detectAndUploadAIBOM(scanPath, gitctx.Collect(scanPath))
		}

		return scanErr

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
	snippetContext := -1
	if cmd.Flags().Changed("snippet-context") {
		snippetContext, _ = cmd.Flags().GetInt("snippet-context")
	}
	excludes, _ := cmd.Flags().GetStringArray("exclude")
	ignoreGlobs, _ := cmd.Flags().GetStringArray("ignore")
	ignoreGit, _ := cmd.Flags().GetBool("ignore-git")
	ignoreBinaries, _ := cmd.Flags().GetBool("ignore-binaries")
	gitHistory, _ := cmd.Flags().GetBool("git-history")
	gitHistoryMaxCommits, _ := cmd.Flags().GetInt("git-history-max-commits")
	gitHistoryMaxFiles, _ := cmd.Flags().GetInt("git-history-max-files")
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
	showPaths, _ := cmd.Flags().GetBool("show-introduced-paths")
	if !showPaths {
		showPaths, _ = cmd.Flags().GetBool("paths")
	}
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
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	scaAutofix, _ := cmd.Flags().GetBool("sca-autofix")
	scaAutofixStrategyRaw, _ := cmd.Flags().GetString("sca-autofix-strategy")
	scaAutofixManifest, _ := cmd.Flags().GetString("sca-autofix-manifest")
	scaAutofixMaxMajorBump, _ := cmd.Flags().GetInt("sca-autofix-max-major-bump")
	yes, _ := cmd.Flags().GetBool("yes")
	pathExplicit := cmd.Flags().Changed("path")

	// Org quality-gate enforcement override. Applied after all nine control
	// flags are read but BEFORE any is consumed (sca-autofix strategy parsing
	// below, runLocalScan, and the gate options). For an authenticated org with
	// a quality-gate policy, a set org value overwrites the local in place —
	// org policy always wins, even over an explicitly-passed flag. Unauthenticated
	// / community scans and orgs without a policy leave these values untouched.
	applyOrgQualityGate(cmd, qualityGateOverridePointers{
		blockEol:               &blockEOL,
		blockMalware:           &blockMalware,
		blockUnpinned:          &blockUnpinned,
		cooldown:               &cooldownDays,
		versionLag:             &versionLag,
		scaAutofixMaxMajorBump: &scaAutofixMaxMajorBump,
		exploits:               &exploitThreshold,
		severity:               &severityThreshold,
		scaAutofixStrategy:     &scaAutofixStrategyRaw,
	})

	scaAutofixStrategy, err := autofix.ValidateStrategy(scaAutofixStrategyRaw)
	if err != nil {
		return err
	}
	if scaAutofix && noSCA {
		fmt.Fprintln(os.Stderr, "Note: --sca-autofix was requested, but SCA is disabled; no autofix will run.")
		scaAutofix = false
	}

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
		// Single-rule mode: run exactly the one named SAST rule.
		// Suppress all manifest/package checks and force SAST enabled.
		noSCA = true
		noLicenses = true
		noContainers = true
		noIAC = true
		noSAST = false
		noSecrets = false
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

	// Specialized subcommands (containers/secrets/iac/sast) are locked to their
	// own rule kind: only rules of these kinds run, embedded *and* externally
	// imported, so a `containers --rule <pack>` scan never bleeds into the
	// pack's secrets/iac/api rules. The generic `scan` command has no lock
	// (lockedKinds == nil) and keeps the "run everything imported" behavior.
	lockedKinds := specializedRuleKinds(cmd.Name())

	// When the user explicitly imports external rule repos into the generic
	// `scan` command, treat that as authoritative intent: don't silently
	// suppress non-SAST kinds (iac, secrets, oci) just because a feature
	// defaulted off. For a locked specialized subcommand the lock wins instead.
	if len(ruleRefs) > 0 && lockedKinds == nil {
		noSecrets = false
		noContainers = false
		noIAC = false
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

	// ── Local malware scan (malscan-engine, in-process) ─────────────────
	// Runs as a pass on `scan`; on `sca` only when --block-malware / org
	// blockMalware is in effect (see shouldRunMalscanPass). It scans the
	// project's dependency install dirs directly, uploads findings to
	// /v2/cli.malscan, and — only when blockMalware is effective — yields a
	// malware quality-gate breach. Computed before any no-files / no-manifest
	// bail so `scan`/`sca --block-malware` still gate on installed-dependency
	// malware in repos with no scannable root manifest; merged into every return.
	malscanBreach := runMalscanPassForScan(cmd, scanPath, blockMalware, gitCtx)

	if len(files) == 0 {
		// WalkForScanFiles only detects dependency manifests and SBOM
		// documents. The SAST-family analyses (sast / secrets / containers /
		// iac) walk the filesystem independently through the SAST engine, so
		// a repo with no manifest (e.g. a data-only repo) must still be
		// secret-scanned. Only short-circuit when no SAST sub-category runs.
		sastFamilyEnabled := !noSAST || !noSecrets || !noContainers || !noIAC
		if !sastFamilyEnabled {
			fmt.Fprintln(os.Stderr, "No scannable files detected.")
			return mergeMalscanBreach(nil, malscanBreach)
		}
	}

	// ── 3. Display detected files ──────────────────────────────────────
	showDetectedForRun := showDetectedFiles || (showAllManifests && noSCA && !noContainers)
	if !resultsOnly && showDetectedForRun {
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
			if !resultsOnly && showDetectedForRun {
				fmt.Fprintf(os.Stderr, "  %-40s manifest    %-10s (%s) %s%s\n",
					f.RelPath, f.ManifestInfo.Ecosystem, f.ManifestInfo.Language, lockStr, supportedStr)
			}
		case scan.FileTypeSPDX:
			if !resultsOnly && showDetectedForRun {
				fmt.Fprintf(os.Stderr, "  %-40s spdx        v%-9s\n", f.RelPath, f.SBOMVersion)
			}
		case scan.FileTypeCycloneDX:
			// Parse the CDX to check the producer.
			cdxBom, cdxErr := parseCDXForScan(f.Path)
			if cdxErr == nil && isVulnetixSCA(cdxBom) {
				if !resultsOnly && showDetectedForRun {
					fmt.Fprintf(os.Stderr, "  %-40s %s\n", f.RelPath,
						display.Teal(t, "[skipped — produced by vulnetix-sca]"))
				}
				if vulnetixSCAVersion(cdxBom) == version {
					vulnetixSeedBOM = cdxBom
				}
				continue
			}
			if cdxErr == nil && cdxBom != nil {
				if !resultsOnly && showDetectedForRun {
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
			} else if showDetectedForRun {
				fmt.Fprintf(os.Stderr, "  %-40s cyclonedx   v%-9s\n", f.RelPath, f.SBOMVersion)
			}
		}
		if f.Supported && f.FileType == scan.FileTypeManifest {
			supportedFiles = append(supportedFiles, f)
		}
	}

	if len(supportedFiles) == 0 {
		// As above: SAST-family analyses do not need a dependency manifest.
		// Continue into runLocalScan (which drives the SAST engine) whenever a
		// SAST sub-category is enabled, and only bail when there is genuinely
		// nothing to scan.
		sastFamilyEnabled := !noSAST || !noSecrets || !noContainers || !noIAC
		if !sastFamilyEnabled {
			fmt.Fprintln(os.Stderr, "\nNo supported manifest files found for scanning.")
			return mergeMalscanBreach(nil, malscanBreach)
		}
	}

	// ── 4. Filter files by feature flags ──────────────────────────────
	supportedFiles = filterFilesByFeature(supportedFiles, noSCA, noContainers, noIAC)

	// ── 5. Collect host environment ─────────────────────────────────────
	sysInfo := gitctx.CollectSystemInfo()

	// ── 6. Run local scan ──────────────────────────────────────────────
	scanErr := runLocalScan(
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
		noSCA,
		noSecrets,
		noContainers,
		noIAC,
		disableDefaultRules,
		ruleRefs,
		ruleRegistry,
		ruleID,
		lockedKinds,
		seedBOM,
		vulnetixSeedBOM,
		gitCtx,
		sysInfo,
		snippetContext,
		dryRun,
		scaAutofix,
		autofix.Options{
			Strategy:     scaAutofixStrategy,
			MaxMajorBump: scaAutofixMaxMajorBump,
			Manifest:     scaAutofixManifest,
			Yes:          yes,
			PathExplicit: pathExplicit,
		},
		nil,
		ignoreGlobs,
		ignoreGit,
		ignoreBinaries,
		gitHistory,
		gitHistoryMaxCommits,
		gitHistoryMaxFiles,
	)

	return mergeMalscanBreach(scanErr, malscanBreach)
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
	noSCA bool,
	noSecrets bool,
	noContainers bool,
	noIAC bool,
	disableDefaultRules bool,
	ruleRefs []sast.RuleRef,
	ruleRegistry string,
	ruleID string,
	lockedKinds []string,
	seedBOM *cdx.BOM,
	vulnetixSeedBOM *cdx.BOM,
	gitCtx *gitctx.GitContext,
	sysInfo *gitctx.SystemInfo,
	snippetContext int,
	dryRun bool,
	scaAutofix bool,
	scaAutofixOpts autofix.Options,
	autofixResolved []*triage.TriageFinding,
	// Secrets-stage options. These only affect the SAST engine when the
	// "secrets" kind is enabled; other kinds ignore them. They are
	// threaded explicitly so that the secrets subcommand can enable
	// binary + git-history inspection without affecting the generic
	// scan behaviour.
	ignoreGlobs []string,
	ignoreGit bool,
	ignoreBinaries bool,
	gitHistory bool,
	gitHistoryMaxCommits int,
	gitHistoryMaxFiles int,
) (retErr error) {
	dctx := display.NewWithProgress(display.ModeText, silent, noProgress)
	scanProgress := dctx.Progress("Scan", 7)
	progressStderr := scanProgress.Writer(os.Stderr)
	scanProgress.SetStage(fmt.Sprintf("Parsing %d detected file(s)", len(files)))
	progressComplete := false
	defer func() {
		if progressComplete {
			return
		}
		if retErr != nil {
			scanProgress.Fail("failed")
			return
		}
		scanProgress.Complete("complete")
	}()
	var localResults []cdx.LocalScanResult
	var allPackages []scan.ScopedPackage
	var manifestGroups []scan.ManifestGroup
	var licensedPackages []license.PackageLicense
	licenseByKey := map[string]string{}
	var allVulns []scan.VulnFinding
	// scaEnrichedFromAPI holds the version-filtered, enriched findings returned
	// by /v2/cli.sca (the sole SCA path). nil only when SCA is skipped.
	var scaEnrichedFromAPI []scan.EnrichedVuln
	// scaInsights holds per-package policy-gate signals returned by /v2/cli.sca
	// (publish dates, version lists, EOL, malware) consumed by the gate block.
	var scaInsights []vdb.CliPackageInsight
	// scaSnapshotUuid is the IngestionSnapshot UUID from /v2/cli.sca; used to
	// report the gate finalization back to the server after evaluation.
	var scaSnapshotUuid string
	var scaSnapshotURL string
	var scaPersistedFindings []vdb.CliFindingResult
	// sarifSnapshots holds per-kind (SAST/Secrets/IaC/Containers) ingestion
	// snapshot links from postScanSARIF, surfaced in the artefact summary.
	var sarifSnapshots []snapshotLink
	// sarifSnapshotUuids maps category → snapshotUuid for SARIF kinds, used to
	// call cli.finalize for each SARIF-only snapshot.
	var sarifSnapshotUuids map[string]string
	var autofixReportPlans []autofix.FixCandidate
	var autofixReportCounts autofix.ProofCounts
	var autofixReportErr error
	containerOnly := noSASTRules && noSCA && noSecrets && !noContainers && noIAC
	// SAST-family-only scans (secrets / sast / iac with no SCA, not container)
	// resolve no packages, so the only thing a CycloneDX BOM could carry is
	// auto-VEX noise from SAST finding state-changes. The SARIF is the report
	// for these scans — never write a stray sbom.cdx.json. (The generic `scan`
	// command does SCA → noSCA is false; container scans are handled above.)
	suppressBOM := noSCA && !containerOnly
	analysisLabel := "SAST"
	analysisTitle := "SAST Analysis"
	sarifFileName := "sast.sarif"
	bomToolName := "vulnetix-sca"
	if containerOnly {
		analysisLabel = "Container"
		analysisTitle = "Container Analysis"
		sarifFileName = "containers.sarif"
		bomToolName = "vulnetix-containers"
	}
	showManifestDetails := !resultsOnly && (showDetectedFiles || (showAllManifests && containerOnly))

	queryCtx := ctx
	if queryCtx == nil {
		queryCtx = context.Background()
	}

	// ── Parse manifests and query VDB (SCA manifests and/or container inputs) ─
	if !noSCA || !noContainers {
		if showManifestDetails {
			fmt.Fprintf(os.Stderr, "\nAnalysing %d file(s)... parsing manifests locally.\n\n", len(files))
		}
		// ── Parse manifests ────────────────────────────────────────────────────
		allPackages = make([]scan.ScopedPackage, 0, 256)

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
				if showManifestDetails {
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
			if f.ManifestInfo.Type == "package.json" && len(pkgs) > 0 && !scan.NpmLockfilePresent(f.Path) {
				resolved, err := scan.ResolveNpmPackageJSONFromNodeModules(f.Path, f.RelPath, pkgs)
				if err != nil {
					return err
				}
				pkgs = resolved
			}

			// Python build-or-lock gate: an unpinned pip manifest (requirements
			// files, pyproject.toml, Pipfile) with no sibling lock must resolve
			// against the installed environment. A confident file that can't be
			// resolved is a fatal error (build the app or generate a lock file); a
			// tentatively-detected file (bare names, ambiguous) that can't be
			// confirmed against installed packages is silently disregarded.
			if scan.IsPythonGatedManifest(f.ManifestInfo.Type) && len(pkgs) > 0 &&
				!scan.RequirementsFullyLocked(pkgs) && !scan.PyLockfilePresent(filepath.Dir(f.Path)) {
				confident := f.ManifestInfo.Confidence != scan.ConfidenceTentative
				resolved, rerr := scan.ResolvePythonRequirementsFromSitePackages(f.Path, f.RelPath, pkgs, confident)
				if rerr != nil {
					if confident {
						return rerr
					}
					continue // tentative + unconfirmed → not a requirements file
				}
				pkgs = resolved
			}

			// Replace absolute path with relative path in each package, and tag
			// manifest-declared packages. The npm node_modules resolver may have
			// already flagged install-only packages as "installed" — don't clobber
			// that; only default the unset (manifest-parsed) packages.
			for i := range pkgs {
				pkgs[i].SourceFile = f.RelPath
				if pkgs[i].SourceType == "" {
					pkgs[i].SourceType = scan.SourceTypeManifest
				}
			}

			// Count by scope for the per-file summary line.
			scopeCounts := map[string]int{}
			for _, p := range pkgs {
				scopeCounts[p.Scope]++
			}
			scopeSummary := formatScopeCounts(scopeCounts)
			if showManifestDetails {
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
		scanProgress.Update(1, fmt.Sprintf("Parsed %d package(s)", len(allPackages)))

		// Build manifest groups (dependency graphs) and run per-package license
		// detection BEFORE the SCA round-trip so the payload can carry accurate
		// introduced-via chains and per-dependency licenses. License detection
		// always runs here so the API receives it; the result is reused for the
		// later SBOM/evaluation step (display is still gated by --no-licenses).
		filePackages := map[string][]scan.ScopedPackage{}
		fileEcosystems := map[string]string{}
		for _, r := range localResults {
			filePackages[r.File.RelPath] = r.Packages
			if r.File.ManifestInfo != nil {
				fileEcosystems[r.File.RelPath] = r.File.ManifestInfo.Ecosystem
			}
		}
		manifestGroups = scan.BuildManifestGroups(filePackages, fileEcosystems)
		scanProgress.SetStage("Building dependency graph")
		scan.PopulateInstalledEdges(manifestGroups, rootPath)

		if len(allPackages) > 0 {
			scanProgress.SetStage(fmt.Sprintf("Resolving package licenses for %d package(s)", len(allPackages)))
			licensedPackages = license.DetectLicenses(allPackages, manifestGroups)
			for _, lp := range licensedPackages {
				if lp.LicenseSpdxID != "" && lp.LicenseSpdxID != "UNKNOWN" {
					licenseByKey[lp.PackageName+"@"+lp.PackageVersion] = lp.LicenseSpdxID
				}
			}
		}
		scanProgress.Update(2, "Prepared dependency metadata")

		// Container-only scans also resolve their parsed components (base images
		// + RUN-installed OS/lang packages) against the VDB so the same CVE data
		// other scanners surface shows up here too. This reuses the SCA path but
		// labels the snapshot as containers and treats an unavailable API as
		// non-fatal (the rego container rules still run).
		runSCAQuery := !noSCA || (containerOnly && len(allPackages) > 0)
		if runSCAQuery {
			// ── Query /v2/cli.sca (one self-healing round-trip for the PURL list) ─
			// The endpoint returns CycloneDX + enriched findings + reachability in a
			// single call, retrying/backing-off and reducing chunk size on transient
			// failure. It is the only SCA path — there is no legacy per-PURL fallback.
			gateOpts := cliSCAGateOptions{
				Cooldown:     cooldownDays > 0,
				VersionLag:   versionLag > 0 || scaAutofix,
				SafeVersions: scaAutofix,
				EOL:          blockEOL,
				Malware:      blockMalware,
			}
			scaToolName := ""
			if containerOnly {
				scaToolName = "vulnetix-containers"
			}
			scanProgress.SetStage(fmt.Sprintf("Querying VDB for %d package(s)", countUniquePackages(allPackages)))
			apiServed, apiVulns, apiEnriched, apiInsights, apiSnapshotUuid, apiSnapshotURL, apiPersistedFindings := tryCliSCA(allPackages, manifestGroups, licenseByKey, gitCtx, sysInfo, rootPath, scaToolName, gateOpts, progressStderr)
			if apiServed {
				allVulns = apiVulns
				scaEnrichedFromAPI = apiEnriched
				scaInsights = apiInsights
				scaSnapshotUuid = apiSnapshotUuid
				scaSnapshotURL = apiSnapshotURL
				scaPersistedFindings = apiPersistedFindings
				scanProgress.Update(3, fmt.Sprintf("VDB returned %d finding(s)", len(allVulns)))
			} else if containerOnly {
				// Container scans degrade gracefully: the misconfiguration rego
				// rules still run and write SARIF, even with no VDB connectivity.
				scanProgress.Update(3, fmt.Sprintf("Parsed %d container component(s); VDB lookup unavailable", len(allPackages)))
			} else {
				// /v2/cli.sca is the only path to the VDB for SCA — the legacy
				// per-PURL lookup has been removed. The endpoint self-heals (retry,
				// backoff, adaptive chunk-size reduction), so apiServed=false means
				// the API is genuinely unusable: a missing/expired credential, bad
				// config, or an unreachable network. Surface that as an actionable
				// error rather than silently degrading.
				return fmt.Errorf("VDB SCA lookup failed: /v2/cli.sca was unavailable (check credentials, config, and network connectivity)")
			}
		} else {
			scanProgress.Update(3, fmt.Sprintf("Parsed %d container component(s)", len(allPackages)))
		}
	} else {
		scanProgress.Update(3, "Skipped SCA package vulnerability lookup")
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
	// Skipped when the API-served path populated enriched data already.
	enrichedVulns := scaEnrichedFromAPI
	if noSCA && !containerOnly {
		scanProgress.Update(4, "Skipped SCA vulnerability enrichment")
	} else {
		scanProgress.Update(4, fmt.Sprintf("Received %d enriched finding(s)", len(enrichedVulns)))
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

	// Manifest groups + dependency-graph edges were built before the SCA
	// round-trip (see above). When SCA is disabled they remain nil, which the
	// downstream SBOM/display code handles as "no dependency tree".
	if manifestGroups == nil {
		filePackages := map[string][]scan.ScopedPackage{}
		fileEcosystems := map[string]string{}
		for _, r := range localResults {
			filePackages[r.File.RelPath] = r.Packages
			if r.File.ManifestInfo != nil {
				fileEcosystems[r.File.RelPath] = r.File.ManifestInfo.Ecosystem
			}
		}
		manifestGroups = scan.BuildManifestGroups(filePackages, fileEcosystems)
		scan.PopulateInstalledEdges(manifestGroups, rootPath)
	}

	if scaAutofix {
		batch := autofix.BuildPlans(enrichedVulns, allPackages, manifestGroups, scaInsights, scaAutofixOpts)
		chosenManifest, chooseErr := chooseAutofixManifest(batch.Plans, scaAutofixOpts.Manifest, scaAutofixOpts.Yes, scaAutofixOpts.PathExplicit)
		if chooseErr != nil {
			return chooseErr
		}
		selected, selectErr := autofix.SelectManifests(batch.Plans, chosenManifest, scaAutofixOpts.Yes)
		if selectErr != nil {
			return selectErr
		}
		selected = rewriteAutofixCommandsForPackageManagers(selected, files)
		selectedCounts := autofix.CountPlans(selected)
		if dryRun {
			scanProgress.Complete("autofix dry run complete")
			progressComplete = true
			printAutofixProposal(selected, selectedCounts)
			return nil
		}
		if len(selected) == 0 {
			fmt.Fprintln(progressStderr, "No SCA autofix candidates found.")
		} else if !hasActionableAutofixPlan(selected) {
			autofixReportPlans = selected
			autofixReportCounts = selectedCounts
			// For packages skipped because every version has vulnerabilities,
			// generate and post a risk-acceptance VEX so the snapshot records
			// the intentional decision.
			skippedNoFix := skippedPlansWithNoSafeVersion(selected)
			if len(skippedNoFix) > 0 {
				vexPath, vexErr := writeRiskAcceptedVEX(rootPath, skippedNoFix, enrichedVulns)
				if vexErr != nil {
					fmt.Fprintf(progressStderr, "  warning: could not write risk-accepted VEX: %v\n", vexErr)
				} else if vexPath != "" {
					fmt.Fprintf(progressStderr, "  VEX (risk-accepted): %s\n", vexPath)
				}
				postRiskAcceptedVEXToSnapshot(scaSnapshotUuid, scaPersistedFindings, skippedNoFix, enrichedVulns, selectedCounts, gitCtx, sysInfo, rootPath, allPackages, progressStderr)
			}
		} else {
			fmt.Fprintln(progressStderr, "Applying SCA autofix plan...")
			if err := autofix.Apply(rootPath, selected); err != nil {
				autofixReportPlans = selected
				autofixReportCounts = selectedCounts
				autofixReportErr = err
				skippedNoFix := skippedPlansWithNoSafeVersion(selected)
				if len(skippedNoFix) > 0 {
					vexPath, vexErr := writeRiskAcceptedVEX(rootPath, skippedNoFix, enrichedVulns)
					if vexErr != nil {
						fmt.Fprintf(progressStderr, "  warning: could not write risk-accepted VEX: %v\n", vexErr)
					} else if vexPath != "" {
						fmt.Fprintf(progressStderr, "  VEX (risk-accepted): %s\n", vexPath)
					}
					postRiskAcceptedVEXToSnapshot(scaSnapshotUuid, scaPersistedFindings, skippedNoFix, enrichedVulns, selectedCounts, gitCtx, sysInfo, rootPath, allPackages, progressStderr)
				}
			} else {
				batches := autofix.GroupBatches(rootPath, selected)
				if err := autofix.RunInstall(queryCtx, batches, false, progressStderr); err != nil {
					autofixReportPlans = selected
					autofixReportCounts = selectedCounts
					autofixReportErr = err
				} else {
					afterEnriched, confirmErr := scanAfterAutofix(files)
					var resolvedFindings []*triage.TriageFinding
					if confirmErr != nil {
						// Don't claim resolutions we couldn't verify — leave
						// resolvedFindings empty so nothing is marked not_affected.
						fmt.Fprintf(progressStderr, "  warning: autofix confirmation scan failed; not marking fixes as resolved: %v\n", confirmErr)
					} else {
						resolvedFindings = resolvedAutofixFindings(selected, afterEnriched)
					}
					vexPath, vexErr := writeAutofixVEX(rootPath, resolvedFindings)
					if vexErr != nil {
						fmt.Fprintf(progressStderr, "  warning: could not write autofix VEX: %v\n", vexErr)
					}
					postAutofixVEXToSnapshot(scaSnapshotUuid, scaPersistedFindings, resolvedFindings, selected, selectedCounts, gitCtx, sysInfo, rootPath, allPackages, progressStderr)
					scanProgress.Complete("autofix applied")
					progressComplete = true
					printAutofixReport(selected, selectedCounts, len(resolvedFindings), nil)
					if vexPath != "" {
						fmt.Fprintf(os.Stdout, "  VEX: %s\n", vexPath)
					}
					fmt.Fprintln(os.Stderr, "Re-scanning to confirm SCA autofix results...")
					return runLocalScan(
						ctx,
						files,
						rootPath,
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
						// SCA-only confirmation re-scan: a dependency fix changes only
						// SCA, so re-running SAST/secrets/containers/IaC just doubles the
						// cost. Keep noSCA as-is so SCA re-runs to confirm the fixes.
						true, // noSASTRules
						noSCA,
						true, // noSecrets
						true, // noContainers
						true, // noIAC
						disableDefaultRules,
						ruleRefs,
						ruleRegistry,
						ruleID,
						lockedKinds,
						seedBOM,
						vulnetixSeedBOM,
						gitCtx,
						sysInfo,
						snippetContext,
						false,
						false,
						autofix.Options{},
						resolvedFindings,
						ignoreGlobs,
						ignoreGit,
						ignoreBinaries,
						gitHistory,
						gitHistoryMaxCommits,
						gitHistoryMaxFiles,
					)
				}
			}
		}
	}

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

	// Stamp this scan's branch / path onto every record we write below, so
	// future scans can branch-gate reconciliation.
	currentBranch := ""
	if gitCtx != nil {
		currentBranch = gitCtx.CurrentBranch
	}
	mem.SetScanContext(&memory.ScanContext{
		Branch: currentBranch,
		Path:   rootPath,
	})

	// installedPkgs lets the reconciler distinguish "dependency removed"
	// from "patched upstream" when an SCA finding disappears.
	installedPkgs := make(map[string]bool, len(allPackages))
	for _, p := range allPackages {
		installedPkgs[strings.ToLower(p.Ecosystem)+":"+strings.ToLower(p.Name)] = true
	}

	var stateChanges []memory.StateChange

	// Write enriched findings to memory unless disabled. Container-only scans
	// record their own findings too (so they persist and show in dashboards),
	// but skip the SCA reconcile-all below: a container scan only sees container
	// packages and must not mark unrelated SCA findings from a prior full scan
	// as remediated.
	if (!noSCA || containerOnly) && !disableMemory && len(enrichedVulns) > 0 {
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

			// Compute introduced dependency paths when --paths was used. FindPathMemo
			// caches per (graph, package) so the same chain is not recomputed for
			// every finding here and again in the pretty-printer.
			if showPaths {
				for _, mg := range manifestGroups {
					if mg.Graph != nil && !mg.Graph.IsDirect(ev.PackageName) {
						if chain := mg.Graph.FindPathMemo(ev.PackageName); len(chain) > 1 {
							ef.IntroducedPaths = append(ef.IntroducedPaths, chain)
						}
					}
				}
			}

			findings = append(findings, ef)
		}
		mem.RecordEnrichedFindings(findings)

		// Reconcile: detect remediated and regressed findings. Only for true SCA
		// scans — see the comment above on why container scans skip this.
		if !noSCA {
			currentCVEs := make(map[string]bool, len(enrichedVulns))
			for _, ev := range enrichedVulns {
				currentCVEs[ev.CveID] = true
			}
			stateChanges = mem.ReconcileTool(memory.ReconcileContext{
				Tool:          memory.ToolSCA,
				CurrentIDs:    currentCVEs,
				InstalledPkgs: installedPkgs,
				Branch:        currentBranch,
				RootPath:      rootPath,
			})
		}
	} else if !noSCA && !disableMemory {
		// No vulns in current scan — reconcile all existing SCA findings.
		stateChanges = mem.ReconcileTool(memory.ReconcileContext{
			Tool:          memory.ToolSCA,
			CurrentIDs:    map[string]bool{},
			InstalledPkgs: installedPkgs,
			Branch:        currentBranch,
			RootPath:      rootPath,
		})
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
		scanProgress.SetStage(fmt.Sprintf("Loading %s rules", strings.ToLower(analysisLabel)))
		modules, merr := sast.LoadAllModules(sast.DefaultRulesFS, disableDefaultRules, ruleRefs, ruleRegistry, progressStderr)
		if merr != nil {
			fmt.Fprintf(progressStderr, "  warning: could not load SAST rules: %v\n", merr)
		}
		if len(modules) > 0 {
			totalLoaded := len(modules)
			fmt.Fprintf(progressStderr, "  Loaded %d rules (pre-filter)\n", totalLoaded)
			if ruleID == "" {
				if len(lockedKinds) > 0 {
					// Specialized subcommand: lock to its kind-set, embedded and
					// externally imported rules alike.
					modules = filterModulesToKinds(modules, lockedKinds)
				} else {
					modules = filterModulesByKind(modules, noSASTRules, noSecrets, noContainers, noIAC)
				}
			}
			modules = filterModulesByID(modules, ruleID)
			eng := sast.NewEngine(modules, rootPath)
			var eerr error
			scanProgress.SetStage(fmt.Sprintf("Evaluating %d %s rule(s)", len(modules), strings.ToLower(analysisLabel)))
			// Binary and git-history scanning only make sense for the secrets
			// subcommand. We enable them automatically when the SAST engine
			// is being driven by kind "secrets"; the user can still turn
			// them off with --ignore-binaries / --ignore-git.
			enableBinaryInspection := !noSecrets
			enableGitHistory := !noSecrets
			sastReport, eerr = eng.Evaluate(sast.EvalOptions{
				MaxDepth:             depth,
				Excludes:             excludes,
				IgnoreGlobs:          ignoreGlobs,
				IgnoreGit:            ignoreGit,
				IgnoreBinaries:       ignoreBinaries,
				GitHistory:           enableGitHistory && gitHistory,
				GitHistoryMaxCommits: gitHistoryMaxCommits,
				GitHistoryMaxFiles:   gitHistoryMaxFiles,
			})
			// Hint the caller that the synthetic-content behaviour was engaged.
			if enableBinaryInspection && !ignoreBinaries {
				_ = enableBinaryInspection // currently a no-op; binary inspection always runs when not ignored
			}
			if eerr != nil {
				fmt.Fprintf(progressStderr, "  warning: SAST evaluation failed: %v\n", eerr)
			}
			if sastReport != nil {
				sastReport.RulesTotal = totalLoaded
			}
		}
		if sastReport != nil {
			rec.SASTRulesLoaded = sastReport.RulesLoaded
			rec.SASTFindingCount = len(sastReport.Findings)

			sarifPath := filepath.Join(vulnetixDir, sarifFileName)
			if !disableMemory {
				// Partition findings by rule Kind: "sast" → SASTFindings map;
				// "secrets" / "iac" / "oci" → categorised findings tagged with
				// the appropriate memory.Tool* value so triage --tool can filter.
				memSAST := make([]memory.SASTFindingRecord, 0, len(sastReport.Findings))
				categorised := map[string]map[string]memory.FindingRecord{} // tool -> id -> record
				currentByTool := map[string]map[string]bool{
					memory.ToolSAST:      {},
					memory.ToolSecrets:   {},
					memory.ToolIaC:       {},
					memory.ToolContainer: {},
				}
				for _, f := range sastReport.Findings {
					kind := ""
					ruleName := ""
					if f.Metadata != nil {
						kind = f.Metadata.Kind
						ruleName = f.Metadata.Name
					}
					switch kind {
					case "secrets", "iac", "oci", "container":
						tool := memory.ToolSecrets
						switch kind {
						case "iac":
							tool = memory.ToolIaC
						case "oci", "container":
							tool = memory.ToolContainer
						}
						bucket, ok := categorised[tool]
						if !ok {
							bucket = map[string]memory.FindingRecord{}
							categorised[tool] = bucket
						}
						bucket[f.Fingerprint] = memory.FindingRecord{
							Aliases:  []string{f.RuleID},
							Severity: f.Severity,
							Source:   "vulnetix-" + tool,
							Locations: []memory.Location{{
								File:      f.ArtifactURI,
								StartLine: f.StartLine,
								EndLine:   f.EndLine,
								Snippet:   f.Snippet,
							}},
						}
						currentByTool[tool][f.Fingerprint] = true
					default:
						memSAST = append(memSAST, memory.SASTFindingRecord{
							RuleID:      f.RuleID,
							RuleName:    ruleName,
							Severity:    f.Severity,
							ArtifactURI: f.ArtifactURI,
							StartLine:   f.StartLine,
							Fingerprint: f.Fingerprint,
							Locations: []memory.Location{{
								File:      f.ArtifactURI,
								StartLine: f.StartLine,
								EndLine:   f.EndLine,
								Snippet:   f.Snippet,
							}},
						})
						currentByTool[memory.ToolSAST][f.Fingerprint] = true
					}
				}
				mem.RecordSASTFindings(memSAST)
				for tool, bucket := range categorised {
					mem.RecordCategorizedFindings(tool, bucket)
				}

				// Verify-then-resolve via on-disk inspection for sast/secrets/iac.
				verifier := func(loc memory.Location) (bool, string) {
					return scan.VerifyLocationGone(rootPath, loc, 5)
				}
				for _, tool := range []string{memory.ToolSAST, memory.ToolSecrets, memory.ToolIaC, memory.ToolContainer} {
					ids := currentByTool[tool]
					changes := mem.ReconcileTool(memory.ReconcileContext{
						Tool:       tool,
						CurrentIDs: ids,
						Branch:     currentBranch,
						RootPath:   rootPath,
						Verifier:   verifier,
					})
					stateChanges = append(stateChanges, changes...)
				}
			}
			// Write SARIF only when findings exist. A clean container scan should
			// not leave a misleading empty SARIF artifact behind.
			if len(sastReport.Findings) > 0 {
				sarifLog := sast.BuildSARIF(sastReport.Findings, sastReport.Rules, version)
				if werr := sast.WriteSARIF(sarifLog, sarifPath); werr != nil {
					fmt.Fprintf(progressStderr, "  warning: could not write %s: %v\n", sarifFileName, werr)
				} else {
					rec.SARIFPath = ".vulnetix/" + sarifFileName
				}
			} else {
				_ = os.Remove(sarifPath)
				if containerOnly {
					_ = os.Remove(filepath.Join(vulnetixDir, "sast.sarif"))
				}
			}

			// Container scans persist their BOM/package inventory through
			// /v2/cli.sca first. The returned snapshot UUID is then supplied to
			// /v2/cli.containers so SARIF findings attach to the same run snapshot.
			if containerOnly && len(allPackages) > 0 && scaSnapshotUuid == "" && !isUnauthenticatedScan() {
				scanProgress.SetStage("Persisting container BOM")
				apiServed, apiInsights, apiSnapshotUuid, apiSnapshotURL, apiPersistedFindings := postCliSCABOM(allPackages, manifestGroups, licenseByKey, gitCtx, sysInfo, rootPath, "vulnetix-containers", io.Discard)
				if apiServed {
					scaInsights = apiInsights
					scaSnapshotUuid = apiSnapshotUuid
					scaSnapshotURL = apiSnapshotURL
					scaPersistedFindings = apiPersistedFindings
				} else if verbose {
					fmt.Fprintln(progressStderr, "  /v2/cli.sca container BOM persistence skipped")
				}
			}

			// Phase-2 persistence: split findings by rule.Kind and POST a
			// SARIF doc per kind to /v2/cli.{sast,secrets,iac,containers}.
			// If /v2/cli.sca already created a snapshot, pass its UUID so SARIF
			// attaches to that snapshot; with no UUID, the SARIF endpoint creates
			// its own. Non-fatal: local SARIF remains authoritative on disk.
			// Skipped for unauthenticated scans — the server persists nothing for
			// the shared community credential, so the calls only burn shared quota.
			if !isUnauthenticatedScan() {
				sarifSnapshots, sarifSnapshotUuids = postScanSARIF(sastReport, gitCtx, rootPath, snippetContext, scaSnapshotUuid, progressStderr)
			}
		}
	}
	if sastReport != nil {
		scanProgress.Update(5, fmt.Sprintf("%s analysis found %d issue(s)", analysisLabel, len(sastReport.Findings)))
	} else {
		scanProgress.Update(5, fmt.Sprintf("%s analysis skipped or produced no findings", analysisLabel))
	}

	scanProgress.SetStage("Persisting scan memory")

	// ── Build .vulnetix/sbom.cdx.json (written below only if non-empty) ──
	scanCtx := &cdx.ScanContext{
		Git:         gitCtx,
		System:      sysInfo,
		ToolVersion: version,
		ToolName:    bomToolName,
	}
	// Prefer vulnetix-sca seed (version-matched) over external CDX seed.
	effectiveSeed := seedBOM
	if vulnetixSeedBOM != nil {
		effectiveSeed = vulnetixSeedBOM
	}
	bom := cdx.BuildFromLocalScan(localResults, "1.7", scanCtx, effectiveSeed)

	// Inject VEX entries for remediated and regressed findings. This is the
	// CycloneDX VEX channel, used only by SCA / container scans that emit a
	// BOM. Static-analysis scans (suppressBOM) emit no BOM, so their finding
	// transitions are attested as a standalone OpenVEX document instead (see
	// writeStaticAnalysisVEX, called below).
	if !suppressBOM {
		for _, sc := range stateChanges {
			vexVuln := cdx.Vulnerability{
				BOMRef: sc.CveID,
				ID:     sc.CveID,
				Source: &cdx.Source{
					Name: "vulnetix-sca",
				},
			}
			vexVuln.Analysis = cdx.AnalysisForStateChange(sc.NewStatus, sc.Comment)
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
	}

	// ── License analysis (unless --no-licenses) ────────────────────────────
	var licenseResult *license.AnalysisResult
	if !noLicenses {
		// Reuse the license detection run before the SCA round-trip; only
		// recompute if it was skipped (e.g. SCA disabled).
		if licensedPackages == nil {
			licensedPackages = license.DetectLicenses(allPackages, manifestGroups)
		}
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

		// Write license findings to memory (persisted by the single
		// memory.Save below, alongside the scan record).
		if !disableMemory && mem != nil && len(licenseResult.Findings) > 0 {
			for _, f := range licenseResult.Findings {
				mem.Findings[f.ID] = memory.FindingRecord{
					Package:         f.Package.PackageName,
					Ecosystem:       f.Package.Ecosystem,
					Severity:        f.Severity,
					Status:          "affected",
					Source:          license.CDXSourceName,
					Versions:        &memory.VersionInfo{Current: f.Package.PackageVersion},
					SourceFiles:     []string{f.Package.SourceFile},
					IntroducedPaths: f.IntroducedPaths,
					PathCount:       f.PathCount,
				}
			}
		}
	}

	// Populate dependency tree from manifest group edges.
	compRefs := cdx.ExportCompRefs(bom)
	bom.Dependencies = cdx.BuildDependencies(manifestGroups, compRefs)

	// Skip writing an empty SBOM: a SAST-only scan resolves 0 packages, so the
	// BOM would have no components or vulnerabilities — the SARIF is the
	// relevant artefact in that case. Don't claim a BOM artefact we didn't write.
	bomWritten := false
	if !suppressBOM && (len(bom.Components) > 0 || len(bom.Vulnerabilities) > 0) {
		if existingBOM, err := parseCDXForScan(sbomPath); err == nil && existingBOM != nil {
			bom = cdx.MergeBOMs(existingBOM, bom)
		}
		if err := writeBOMToFile(bom, sbomPath); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: could not write BOM: %v\n", err)
		} else {
			bomWritten = true
		}
	}
	if !bomWritten {
		rec.SBOMPath = "" // omitempty → not serialised into memory.yaml
	}

	// Static-analysis scans (secrets / sast / iac) emit SARIF + OpenVEX, never a
	// CycloneDX BOM. Attest any finding transitions as an OpenVEX document.
	if suppressBOM {
		if vexPath, vexErr := writeStaticAnalysisVEX(rootPath, stateChanges); vexErr != nil {
			fmt.Fprintf(os.Stderr, "  warning: could not write OpenVEX: %v\n", vexErr)
		} else if vexPath != "" {
			fmt.Fprintf(os.Stdout, "  %s VEX:      %s\n", display.CheckMark(display.NewTerminal()), vexPath)
		}
	}

	if !disableMemory {
		recordAutofixMemoryEvents(mem, autofixResolved)
	}
	mem.RecordScan(rec)
	if err := memory.Save(vulnetixDir, mem); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: could not update memory.yaml: %v\n", err)
	}
	scanProgress.Update(6, "Wrote local scan state")

	// ── Quality gate evaluation ───────────────────────────────────────────
	// Evaluated after writing artefacts so that the SBOM and memory.yaml are
	// always written regardless of exit code, giving CI pipelines access to
	// the full findings even when the build is broken.
	var breaches []GateBreach

	// Index /v2/cli.sca per-package insights by the exact PURL the CLI sent
	// (the server echoes it back verbatim), so the cooldown / version-lag /
	// EOL / malware gates read freshly-resolved signals from the single
	// round-trip instead of extra per-package API calls.
	insightByPurl := make(map[string]vdb.CliPackageInsight, len(scaInsights))
	for _, ins := range scaInsights {
		if ins.Purl != "" {
			insightByPurl[ins.Purl] = ins
		}
	}

	// Gate 1: malware — CVE-flagged malicious packages (from enrichment) plus
	// the direct malicious-package verdict the server returns in PackageInsights
	// (catches malicious packages even when no version-specific CVE resolved).
	if blockMalware {
		maliciousNames := map[string]bool{}
		var malwareLabels []string
		for _, ev := range enrichedVulns {
			if ev.IsMalicious && !maliciousNames[ev.PackageName] {
				maliciousNames[ev.PackageName] = true
				malwareLabels = append(malwareLabels, ev.PackageName)
			}
		}
		for _, ins := range scaInsights {
			if ins.IsMalicious && !maliciousNames[ins.Name] {
				maliciousNames[ins.Name] = true
				malwareLabels = append(malwareLabels, ins.Name)
			}
		}
		if len(malwareLabels) > 0 {
			breaches = append(breaches, GateBreach{
				Gate:  "malware",
				Count: len(malwareLabels),
				Message: fmt.Sprintf("--block-malware: %s flagged as malicious: %s",
					pluralise("package", len(malwareLabels)),
					strings.Join(malwareLabels, ", ")),
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
				Message: fmt.Sprintf("--exploits %s: %s at or above the threshold",
					exploitThreshold, pluralise("vulnerability", len(exploitVulns))),
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
				Message: fmt.Sprintf("--severity %s: %s at or above the threshold",
					severityThreshold, pluralise("vulnerability", len(severityVulns))),
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
				Message: fmt.Sprintf("--block-eol: %s end-of-life: %s",
					pluralise("runtime", len(eolViolations)),
					strings.Join(eolViolations, ", ")),
			})
		}

		// Package-level EOL — from /v2/cli.sca PackageInsights (the server maps
		// each package to its EolProduct/EolRelease and matches the installed
		// version's release line). Packages with no EOL row are skipped.
		seenPkgEol := map[string]bool{}
		var eolPkgList []string
		for _, p := range allPackages {
			if p.Version == "" {
				continue
			}
			purl := cdx.BuildLocalPurl(p.Name, p.Version, p.Ecosystem)
			if purl == "" || seenPkgEol[purl] {
				continue
			}
			seenPkgEol[purl] = true
			ins, ok := insightByPurl[purl]
			if !ok || !ins.IsEOL {
				continue
			}
			label := fmt.Sprintf("%s@%s (%s)", p.Name, p.Version, p.Ecosystem)
			if ins.EOLFrom != "" {
				label = fmt.Sprintf("%s@%s (%s, EOL since %s)", p.Name, p.Version, p.Ecosystem, ins.EOLFrom)
			}
			eolPkgList = append(eolPkgList, label)
		}
		if len(eolPkgList) > 0 {
			breaches = append(breaches, GateBreach{
				Gate:  "eol",
				Count: len(eolPkgList),
				Message: fmt.Sprintf("--block-eol: %s end-of-life: %s",
					pluralise("package", len(eolPkgList)),
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
				Message: fmt.Sprintf("--block-unpinned: %s with an unpinned version spec",
					pluralise("dependency", len(unpinnedPkgs))),
			})
		}
	}

	// Gates 6 & 7: version-lag and cooldown — both read the per-package signals
	// returned by /v2/cli.sca (publish dates + version lists), so there are no
	// extra per-package round-trips here.
	if versionLag > 0 || cooldownDays > 0 {
		// Gate 6: version-lag — rank the installed version against the package's
		// recent releases (newest-first by semver).
		if versionLag > 0 {
			seenLag := map[string]bool{}
			var lagViolations []string
			for _, p := range allPackages {
				key := p.Name + "::" + p.Ecosystem
				if seenLag[key] {
					continue
				}
				seenLag[key] = true
				ins, ok := insightByPurl[cdx.BuildLocalPurl(p.Name, p.Version, p.Ecosystem)]
				if !ok || len(ins.LatestVersions) == 0 {
					continue
				}
				recs := make([]vdb.VersionRecord, 0, len(ins.LatestVersions))
				for _, s := range ins.LatestVersions {
					recs = append(recs, vdb.VersionRecord{Version: s.Version})
				}
				sorted := sortVersionsDesc(recs)
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
					Message: fmt.Sprintf("--version-lag %d: %s within the %d most recent %s: %s",
						versionLag, pluralise("dependency", len(lagViolations)),
						versionLag, plural("release", versionLag),
						strings.Join(lagViolations, ", ")),
				})
			}
		}

		// Gate 7: cooldown — uses the installed version's publish date, which the
		// server resolves cache-first from the Dependency table and refreshes
		// from deps.dev on a miss, so the date is always current.
		if cooldownDays > 0 {
			cutoffMs := time.Now().UTC().AddDate(0, 0, -cooldownDays).UnixMilli()
			seenCooldown := map[string]bool{}
			var cooldownViolations []string
			for _, p := range allPackages {
				key := p.Name + "::" + p.Ecosystem
				if seenCooldown[key] {
					continue
				}
				seenCooldown[key] = true
				ins, ok := insightByPurl[cdx.BuildLocalPurl(p.Name, p.Version, p.Ecosystem)]
				if !ok || ins.PublishedAt == nil {
					continue
				}
				if *ins.PublishedAt > cutoffMs {
					t := time.UnixMilli(*ins.PublishedAt).UTC()
					cooldownViolations = append(cooldownViolations,
						fmt.Sprintf("%s@%s (published %s)", p.Name, p.Version, t.Format("2006-01-02")))
				}
			}
			if len(cooldownViolations) > 0 {
				breaches = append(breaches, GateBreach{
					Gate:  "cooldown",
					Count: len(cooldownViolations),
					Message: fmt.Sprintf("--cooldown %d: %s published within the last %d %s: %s",
						cooldownDays, pluralise("dependency", len(cooldownViolations)),
						cooldownDays, plural("day", cooldownDays),
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
				Message: fmt.Sprintf("--severity %s: %s at or above the threshold",
					severityThreshold, pluralise("SAST finding", n)),
			})
		}
	}

	// ── Report finalization ───────────────────────────────────────────────
	// Once all gates are decided, report the outcome (exit code + per-gate
	// breaches) back to the server against the scan's snapshot so the env row
	// records what the gates decided. Runs on every scan (pass or fail) and is
	// best-effort — it never affects this scan's own exit code.
	//
	// controlFlags records EVERY control flag the user set — not just the gates
	// that breached — so the GUI can reconstruct the full invocation.
	controlFlags := []vdb.CliControlFlag{}
	if severityThreshold != "" {
		controlFlags = append(controlFlags, vdb.CliControlFlag{Flag: "--severity", Value: severityThreshold})
	}
	if exploitThreshold != "" {
		controlFlags = append(controlFlags, vdb.CliControlFlag{Flag: "--exploits", Value: exploitThreshold})
	}
	if versionLag > 0 {
		controlFlags = append(controlFlags, vdb.CliControlFlag{Flag: "--version-lag", Value: fmt.Sprintf("%d", versionLag)})
	}
	if cooldownDays > 0 {
		controlFlags = append(controlFlags, vdb.CliControlFlag{Flag: "--cooldown", Value: fmt.Sprintf("%d", cooldownDays)})
	}
	if blockMalware {
		controlFlags = append(controlFlags, vdb.CliControlFlag{Flag: "--block-malware", Value: "true"})
	}
	if blockEOL {
		controlFlags = append(controlFlags, vdb.CliControlFlag{Flag: "--block-eol", Value: "true"})
	}
	if blockUnpinned {
		controlFlags = append(controlFlags, vdb.CliControlFlag{Flag: "--block-unpinned", Value: "true"})
	}
	if scaAutofix {
		controlFlags = append(controlFlags, vdb.CliControlFlag{Flag: "--sca-autofix", Value: "true"})
		controlFlags = append(controlFlags, vdb.CliControlFlag{Flag: "--sca-autofix-strategy", Value: string(scaAutofixOpts.Strategy)})
		if scaAutofixOpts.Manifest != "" {
			controlFlags = append(controlFlags, vdb.CliControlFlag{Flag: "--sca-autofix-manifest", Value: scaAutofixOpts.Manifest})
		}
		if scaAutofixOpts.MaxMajorBump != 0 {
			controlFlags = append(controlFlags, vdb.CliControlFlag{Flag: "--sca-autofix-max-major-bump", Value: fmt.Sprintf("%d", scaAutofixOpts.MaxMajorBump)})
		}
	}
	finalizationBreaches := breaches
	if autofixReportErr != nil {
		finalizationBreaches = append(append([]GateBreach(nil), breaches...), GateBreach{
			Gate:    "sca-autofix",
			Count:   1,
			Message: fmt.Sprintf("--sca-autofix failed: %v", autofixReportErr),
		})
	}
	finalizedSnapshots := map[string]bool{}
	if scaSnapshotUuid != "" {
		reportScanFinalization(scaSnapshotUuid, finalizationBreaches, controlFlags, gitCtx, sysInfo)
		finalizedSnapshots[scaSnapshotUuid] = true
	}
	for _, uuid := range sarifSnapshotUuids {
		if uuid == "" || finalizedSnapshots[uuid] {
			continue
		}
		reportScanFinalization(uuid, finalizationBreaches, controlFlags, gitCtx, sysInfo)
		finalizedSnapshots[uuid] = true
	}
	scanProgress.Update(7, "Evaluated quality gates")
	scanProgress.Complete("scan complete")
	progressComplete = true

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

	// Stdout format: emit machine-readable JSON, no pretty output. The pretty
	// artefact summary is skipped, so echo any ingestion snapshot URLs to stderr
	// instead of losing them.
	if outCfg.stdoutFmt == "json-cyclonedx" {
		outBOM := cdx.BuildFromLocalScan(localResults, "1.7", scanCtx, seedBOM)
		outBOM.NormalizeForSchema()
		if err := outBOM.WriteJSON(os.Stdout); err != nil {
			return err
		}
		printSnapshotsToStderr(sarifSnapshots)
		if len(breaches) > 0 {
			return &MultiPolicyBreachError{Breaches: breaches}
		}
		if autofixReportErr != nil {
			return autofixReportErr
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
		printSnapshotsToStderr(sarifSnapshots)
		if len(breaches) > 0 {
			return &MultiPolicyBreachError{Breaches: breaches}
		}
		if autofixReportErr != nil {
			return autofixReportErr
		}
		return nil
	}

	// Pretty output (default, or when only file outputs were requested).
	// Only surface the BOM artefact line when we actually wrote one; surface
	// the SARIF line whenever a SAST report (and thus sast.sarif) was produced.
	displaySBOM := ""
	if bomWritten {
		displaySBOM = sbomPath
	}
	sarifPath := ""
	if sastReport != nil && len(sastReport.Findings) > 0 {
		sarifPath = filepath.Join(vulnetixDir, sarifFileName)
	}
	// SCA summary (vuln tables + "X packages | Y vulnerabilities") only when SCA
	// ran. For a SAST-only scan the SCA headline is meaningless, so show a
	// SAST-specific headline instead.
	//
	// Order: table → SCA Autofix (if any) → summary footer → artifact links.
	// This keeps the snapshot URL visible at the very end.
	var scaTotalPkgs, scaTotalVulns int
	if !noSCA {
		scaTotalPkgs, scaTotalVulns = printPrettyScanSummary(enrichedVulns, manifestGroups, allPackages, showPaths, noExploits, noRemediation, resultsOnly)
		if autofixReportPlans != nil {
			printAutofixReport(autofixReportPlans, autofixReportCounts, 0, autofixReportErr)
		}
		printScanSummaryFooter(scaTotalPkgs, scaTotalVulns, enrichedVulns)
	} else if sastReport != nil {
		sast.PrintHeadlineWithLabel(sastReport, analysisLabel)
	}
	if licenseResult != nil && len(licenseResult.Findings) > 0 {
		printPrettyLicenseSummary(licenseResult, sbomPath, vulnetixDir)
	}
	sast.PrintPrettySummaryWithTitle(sastReport, resultsOnly, analysisTitle)

	// Artefact links print last, after all analysis output.
	printScanArtifacts(displaySBOM, sarifPath, vulnetixDir, rulesPath, scaSnapshotURL, sarifSnapshots)
	if isUnauthenticatedScan() {
		printCommunitySignupReminder()
	}

	if len(breaches) > 0 {
		fmt.Fprintln(os.Stderr)
		for _, b := range breaches {
			fmt.Fprintf(os.Stderr, "  ✗ %s\n", b.Message)
		}
		return &MultiPolicyBreachError{Breaches: breaches}
	}
	if autofixReportErr != nil {
		return autofixReportErr
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
	if showDetectedFiles {
		fmt.Fprintln(os.Stderr, "Detected files:")
	}
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
			if showDetectedFiles {
				fmt.Fprintf(os.Stderr, "  %-40s manifest    %-10s (%s) %s%s\n",
					f.RelPath, f.ManifestInfo.Ecosystem, f.ManifestInfo.Language, lockStr, supportedStr)
			}
		case scan.FileTypeSPDX:
			if showDetectedFiles {
				fmt.Fprintf(os.Stderr, "  %-40s spdx        v%-9s\n", f.RelPath, f.SBOMVersion)
			}
		case scan.FileTypeCycloneDX:
			cdxBom, cdxErr := parseCDXForScan(f.Path)
			if cdxErr == nil && isVulnetixSCA(cdxBom) {
				if showDetectedFiles {
					fmt.Fprintf(os.Stderr, "  %-40s %s\n", f.RelPath,
						display.Teal(t, "[skipped — produced by vulnetix-sca]"))
				}
				continue
			}
			if cdxErr == nil && cdxBom != nil && len(cdxBom.Components) > 0 {
				if showDetectedFiles {
					fmt.Fprintf(os.Stderr, "  %-40s cyclonedx   v%-8s (%d comp, %d vulns)\n",
						f.RelPath, f.SBOMVersion, len(cdxBom.Components), len(cdxBom.Vulnerabilities))
				}
				f.Supported = true
				supportedFiles = append(supportedFiles, f)
			} else if showDetectedFiles {
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
			if showDetectedFiles {
				fmt.Fprintf(os.Stderr, "  %-40s %d packages%s\n",
					f.RelPath, len(pkgs), formatScopeCounts(scopeCounts))
			}
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
		if showDetectedFiles {
			fmt.Fprintf(os.Stderr, "  %-40s %d packages%s\n",
				f.RelPath, len(pkgs), formatScopeCounts(scopeCounts))
		}
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
	resultsOnly bool,
) (int, int) {
	// --results-only: stay silent when there are no findings.
	if resultsOnly && len(enrichedVulns) == 0 {
		return 0, 0
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
		// Dependency relationship: direct (declared in manifest) or
		// transitive (pulled in by another dep). Replaces the older
		// asterisk footnote convention.
		{Header: "Type", MinWidth: 6, MaxWidth: 10, Color: func(s string) string {
			switch strings.ToLower(strings.TrimSpace(s)) {
			case "direct":
				return display.Accent(t, s)
			case "transitive":
				return display.Muted(t, s)
			default:
				return s
			}
		}},
		// Reachability outcome from the local analysis. "direct" /
		// "transitive" labels here describe call-graph reach (tree-sitter
		// queries that ran against installed-package source vs first-party
		// source); "semantic" is the import/symbol grep fallback; empty =
		// no data to analyse.
		{Header: "Reach", MinWidth: 6, MaxWidth: 12, Color: func(s string) string {
			switch strings.ToLower(strings.TrimSpace(s)) {
			case "direct":
				return display.ErrorStyle(t, s)
			case "transitive":
				return display.Accent(t, s)
			case "semantic":
				return display.Accent(t, s)
			case "unreachable":
				return display.Success(t, s)
			default:
				return display.Muted(t, s)
			}
		}},
	}

	var allRows [][]string
	var allPaths []pathEntry

	// ── First pass: build unified table rows ──────────────────────────────
	for _, res := range prepared {
		mg := res.mg
		primaryFile := res.primaryFile
		dedupedVulns := res.dedupedVulns

		if len(dedupedVulns) == 0 {
			if !showAllManifests {
				continue
			}
			// Sentinel row so the file still appears in the table.
			row := make([]string, 17)
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
			// Type column (Direct/Transitive) — replaces the asterisk footnote.
			depType := "direct"
			if mg.Graph != nil && !mg.Graph.IsDirect(v.PackageName) {
				depType = "transitive"
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

			reach := v.Reachability

			allRows = append(allRows, []string{
				fileCell, vulnID, pkg, mal, maxSev,
				cvss, cvssSev, epss, epssSev,
				ssvc, ssvcSev, cess, cesSev, expl, fix, matchMethod, depType, reach,
			})

			if showPaths && mg.Graph != nil && !mg.Graph.IsDirect(v.PackageName) {
				if chain := mg.Graph.FindPathMemo(v.PackageName); len(chain) > 1 {
					allPaths = append(allPaths, pathEntry{pkgName: v.PackageName, chain: chain})
				}
			}
		}
	}

	// ── Print unified table ───────────────────────────────────────────────
	fmt.Fprintln(os.Stdout)
	if len(allRows) > 0 {
		fmt.Fprintln(os.Stdout, display.Table(t, cols, allRows))
	}

	// ── Semantic Reachability ─────────────────────────────────────────────
	// Per-CVE file:line hits from the symbol-grep fallback. Shown
	// independently of --show-introduced-paths because the file:line
	// pinpoints where the affected dep is actually referenced in source.
	if !resultsOnly {
		type semHit struct {
			cveID string
			pkg   string
			match scan.SemanticMatch
		}
		var sem []semHit
		for _, res := range prepared {
			for _, v := range res.dedupedVulns {
				for _, m := range v.SemanticMatches {
					sem = append(sem, semHit{cveID: v.CveID, pkg: v.PackageName, match: m})
				}
			}
		}
		if len(sem) > 0 {
			fmt.Fprintln(os.Stdout)
			fmt.Fprintln(os.Stdout, display.Subheader(t, "Semantic Reachability"))
			fmt.Fprintln(os.Stdout, display.Muted(t, "  Affected symbol referenced literally in your source — lower confidence than tree-sitter call-graph reach but a strong intent signal."))
			seen := map[string]bool{}
			for _, h := range sem {
				loc := h.match.File
				if h.match.Line > 0 {
					loc = fmt.Sprintf("%s:%d", h.match.File, h.match.Line)
				}
				key := h.cveID + "|" + loc + "|" + h.match.Symbol
				if seen[key] {
					continue
				}
				seen[key] = true
				fmt.Fprintf(os.Stdout, "  %s  %s  %s  %s\n",
					display.Bold(t, h.cveID),
					display.Muted(t, h.pkg),
					h.match.Symbol,
					display.Muted(t, loc))
			}
		}
	}

	// ── Introduced Via ────────────────────────────────────────────────────
	// Only shown for transitive deps — direct deps are introduced by the
	// manifest itself, so a one-link "chain" would be redundant.
	if showPaths && len(allPaths) > 0 {
		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, display.Subheader(t, "Introduced Via"))
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

	totalPkgs := len(countUniqueMap(allPackages))
	return totalPkgs, totalVulns
}

// printScanSummaryFooter prints the closing divider, "N packages | M vulnerabilities"
// summary line, and optional reachability breakdown. Called after SCA Autofix output
// so the final artifact links come last.
func printScanSummaryFooter(totalPkgs, totalVulns int, enrichedVulns []scan.EnrichedVuln) {
	t := display.NewTerminal()
	fmt.Fprintln(os.Stdout, display.Divider(t))
	summary := fmt.Sprintf("  %d packages | %s", totalPkgs, pluralise("vulnerability", totalVulns))
	fmt.Fprintln(os.Stdout, display.Bold(t, summary))
	if anyReachabilityAssessed(enrichedVulns) {
		assessed, reachable, notReachable, notAssessable := countReachability(enrichedVulns)
		fmt.Fprintf(os.Stdout, "  Reachability: %d assessed, %d reachable, %d not reachable, %d not assessable/no data\n",
			assessed, reachable, notReachable, notAssessable)
	}
	fmt.Fprintln(os.Stdout)
}

func printAutofixProposal(plans []autofix.FixCandidate, counts autofix.ProofCounts) {
	t := display.NewTerminal()
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, display.Divider(t))
	fmt.Fprintln(os.Stdout, display.Subheader(t, "SCA Autofix Dry Run"))
	if len(plans) == 0 {
		fmt.Fprintln(os.Stdout, "  No autofix candidates found.")
		return
	}
	for _, p := range plans {
		status := "will fix"
		if p.Skipped {
			status = "manual"
		}
		target := p.TargetVer
		if target == "" {
			target = "<no vetted target>"
		}
		fmt.Fprintf(os.Stdout, "  %s  %s %s -> %s  %s  %s\n",
			display.Bold(t, status),
			p.PackageName,
			p.CurrentVer,
			target,
			p.Method,
			display.Muted(t, p.SourceFile))
		if p.Reason != "" {
			fmt.Fprintf(os.Stdout, "    %s\n", p.Reason)
		}
		if p.SkipReason != "" {
			fmt.Fprintf(os.Stdout, "    skipped: %s\n", p.SkipReason)
		}
		if p.Command != "" {
			fmt.Fprintf(os.Stdout, "    $ %s\n", p.Command)
		}
	}
	printAutofixCounts(counts)
	fmt.Fprintln(os.Stdout, "  Dry run only: no manifests changed, no install ran, no rescan ran.")
	fmt.Fprintln(os.Stdout, display.Divider(t))
}

func printAutofixReport(plans []autofix.FixCandidate, counts autofix.ProofCounts, applied int, err error) {
	t := display.NewTerminal()
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, display.Divider(t))
	fmt.Fprintln(os.Stdout, display.Subheader(t, "SCA Autofix"))
	if err != nil {
		fmt.Fprintf(os.Stdout, "  %s %v\n", display.ErrorStyle(t, "failed:"), err)
	}
	if applied > 0 {
		fmt.Fprintf(os.Stdout, "  Resolved findings confirmed: %d\n", applied)
	}
	for _, p := range plans {
		if p.Skipped {
			fmt.Fprintf(os.Stdout, "  Not fixed: %s %s (%s)\n", p.PackageName, p.CurrentVer, p.SkipReason)
			if p.Command != "" {
				fmt.Fprintf(os.Stdout, "    manual: %s\n", p.Command)
			}
			if len(p.RejectedVersions) > 0 {
				fmt.Fprintf(os.Stdout, "    Rationale (safest strategy): no vulnerability-free version available\n")
				for _, rv := range p.RejectedVersions {
					marker := ""
					if rv.Version == p.CurrentVer {
						marker = "  ← installed"
					}
					switch {
					case rv.IsMalware:
						fmt.Fprintf(os.Stdout, "      • %s: malware%s\n", rv.Version, marker)
					case rv.ExplCount > 0:
						fmt.Fprintf(os.Stdout, "      • %s: %d vuln(s), %d exploit(s)%s\n", rv.Version, rv.VulnCount, rv.ExplCount, marker)
					default:
						fmt.Fprintf(os.Stdout, "      • %s: %d vuln(s)%s\n", rv.Version, rv.VulnCount, marker)
					}
				}
				latest := p.LatestAvailable
				if latest == "" {
					latest = p.CurrentVer
				}
				fmt.Fprintf(os.Stdout, "    Upgrading to latest (%s) would not reduce risk; staying at current version is risk-accepted.\n", latest)
			}
			continue
		}
		status := "Fixed"
		if err != nil {
			status = "Planned"
		}
		fmt.Fprintf(os.Stdout, "  %s: %s %s -> %s  %s  %s\n",
			status, p.PackageName, p.CurrentVer, p.TargetVer, p.Method, display.Muted(t, p.SourceFile))
		if p.Command != "" {
			fmt.Fprintf(os.Stdout, "    used: %s\n", p.Command)
		}
	}
	printAutofixCounts(counts)
	fmt.Fprintln(os.Stdout)
	fmt.Fprintf(os.Stdout, "  %s Commit manifest and lockfile changes together.\n", display.Bold(t, "IMPORTANT:"))
	fmt.Fprintln(os.Stdout, "  Include the edited manifest and regenerated lockfile in the same commit.")
	fmt.Fprintln(os.Stdout, display.Divider(t))
}

func printAutofixCounts(counts autofix.ProofCounts) {
	fmt.Fprintf(os.Stdout, "  Proof-of-work: %d direct, %d transitive via parent-update, %d transitive via parent-upgrade, %d transitive via override, %d unresolved deep chains\n",
		counts.Direct, counts.TransitiveParentUpdate, counts.TransitiveParentUpgrade, counts.TransitiveOverride, counts.UnresolvedDeepChains)
}

func hasActionableAutofixPlan(plans []autofix.FixCandidate) bool {
	for _, p := range plans {
		if !p.Skipped {
			return true
		}
	}
	return false
}

func rewriteAutofixCommandsForPackageManagers(plans []autofix.FixCandidate, files []scan.DetectedFile) []autofix.FixCandidate {
	if len(plans) == 0 {
		return plans
	}
	presentFiles := make([]string, 0, len(files))
	for _, f := range files {
		if f.RelPath != "" {
			presentFiles = append(presentFiles, filepath.Base(f.RelPath))
		}
	}
	// Which resolver binaries are actually installed on this host, by ecosystem.
	detected := map[string]bool{}
	detectedByEcosystem := map[string][]string{}
	for _, rb := range scan.ResolvePackageManagerBinaries(presentFiles) {
		if rb.Detected {
			detected[rb.Binary] = true
			detectedByEcosystem[rb.Ecosystem] = append(detectedByEcosystem[rb.Ecosystem], rb.Binary)
		}
	}

	pmByDir := packageManagersByDir(files)
	yarnModernByDir := yarnModernByDir(files)
	out := append([]autofix.FixCandidate(nil), plans...)
	for i := range out {
		eco := strings.ToLower(out[i].Ecosystem)
		dir := filepath.Dir(filepath.Clean(out[i].SourceFile))
		pm := pmByDir[dir]
		if pm == "" {
			pm = defaultPackageManagerForEcosystem(eco)
		}
		// Prefer the lockfile-implied PM; if it is not installed, fall back to any
		// installed resolver for the same ecosystem. If none is installed we
		// cannot install/re-resolve, so mark the fix manual rather than emit a
		// command that will fail.
		if pm != "" && !detected[pm] {
			if alt := firstInstalledForEcosystem(eco, detectedByEcosystem); alt != "" {
				pm = alt
			} else if requiresInstalledManager(eco) && !out[i].Skipped {
				out[i].Skipped = true
				out[i].SkipReason = fmt.Sprintf("no %s package manager detected on PATH to apply and re-resolve the fix", eco)
				continue
			}
		}
		out[i].PackageManager = pm
		switch eco {
		case "npm":
			out[i].Command = npmCommandForManager(out[i], pm, yarnModernByDir[dir])
		case "pypi":
			out[i].Command = pythonCommandForManager(out[i], pm)
		}
	}
	return out
}

// defaultPackageManagerForEcosystem returns the conventional resolver when no
// lockfile narrowed the choice.
func defaultPackageManagerForEcosystem(ecosystem string) string {
	switch ecosystem {
	case "npm":
		return "npm"
	case "pypi":
		return "pip"
	case "golang":
		return "go"
	case "cargo":
		return "cargo"
	case "composer":
		return "composer"
	case "rubygems":
		return "bundle"
	case "maven":
		return "mvn"
	default:
		return ""
	}
}

func firstInstalledForEcosystem(ecosystem string, detectedByEcosystem map[string][]string) string {
	bins := detectedByEcosystem[ecosystem]
	if len(bins) == 0 {
		return ""
	}
	return bins[0]
}

// requiresInstalledManager reports whether applying a fix for the ecosystem
// requires an installed resolver to regenerate the lockfile.
func requiresInstalledManager(ecosystem string) bool {
	switch ecosystem {
	case "npm", "pypi", "golang", "cargo", "composer", "rubygems", "maven":
		return true
	default:
		return false
	}
}

func packageManagersByDir(files []scan.DetectedFile) map[string]string {
	out := map[string]string{}
	for _, f := range files {
		dir := filepath.Dir(filepath.Clean(f.RelPath))
		base := filepath.Base(f.RelPath)
		switch base {
		case "package-lock.json":
			out[dir] = "npm"
		case "yarn.lock":
			out[dir] = "yarn"
		case "pnpm-lock.yaml":
			out[dir] = "pnpm"
		case "bun.lockb":
			out[dir] = "bun"
		case "uv.lock":
			out[dir] = "uv"
		case "poetry.lock":
			out[dir] = "poetry"
		case "pdm.lock":
			out[dir] = "pdm"
		case "Pipfile.lock":
			out[dir] = "pipenv"
		}
	}
	return out
}

func yarnModernByDir(files []scan.DetectedFile) map[string]bool {
	out := map[string]bool{}
	for _, f := range files {
		dir := filepath.Dir(filepath.Clean(f.RelPath))
		base := filepath.Base(f.RelPath)
		if base == "package.json" && packageJSONDeclaresModernYarn(f.Path) {
			out[dir] = true
		}
		if base == "yarn.lock" && yarnLockIsModern(f.Path) {
			out[dir] = true
		}
		if base == "yarn.lock" && f.Path != "" {
			if _, err := os.Stat(filepath.Join(filepath.Dir(f.Path), ".yarnrc.yml")); err == nil {
				out[dir] = true
			}
		}
	}
	return out
}

func packageJSONDeclaresModernYarn(path string) bool {
	if path == "" {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var manifest struct {
		PackageManager string `json:"packageManager"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return false
	}
	pm := strings.ToLower(strings.TrimSpace(manifest.PackageManager))
	if !strings.HasPrefix(pm, "yarn@") {
		return false
	}
	ver := strings.TrimPrefix(pm, "yarn@")
	return ver != "" && !strings.HasPrefix(ver, "1.")
}

func yarnLockIsModern(path string) bool {
	if path == "" {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	text := string(data)
	if strings.Contains(text, "# yarn lockfile v1") {
		return false
	}
	return strings.Contains(text, "\n__metadata:") || strings.HasPrefix(text, "__metadata:")
}

func npmCommandForManager(p autofix.FixCandidate, pm string, modernYarn bool) string {
	name := p.PackageName
	if p.Method == autofix.MethodParentUpgrade && p.ParentName != "" {
		name = p.ParentName
	}
	switch p.Method {
	case autofix.MethodDirectBump, autofix.MethodOverride:
		switch pm {
		case "yarn", "pnpm", "bun":
			return pm + " install"
		default:
			return "npm install"
		}
	case autofix.MethodParentUpdate:
		if p.ParentName != "" {
			name = p.ParentName
		}
		switch pm {
		case "yarn":
			if modernYarn {
				return "yarn up " + name
			}
			return "yarn upgrade " + name
		case "pnpm", "bun":
			return pm + " update " + name
		default:
			return "npm update " + name
		}
	case autofix.MethodParentUpgrade:
		// Install the PARENT at its resolved version (ParentTarget), not the child's
		// safe version (TargetVer) — upgrading the parent is what pulls the safe child.
		target := p.ParentTarget
		if target == "" {
			target = "<safe-version>"
		}
		switch pm {
		case "yarn":
			if modernYarn {
				return "yarn up " + name + "@" + target
			}
			return "yarn add " + name + "@" + target
		case "pnpm", "bun":
			return pm + " add " + name + "@" + target
		default:
			return "npm install " + name + "@" + target
		}
	default:
		return p.Command
	}
}

func pythonCommandForManager(p autofix.FixCandidate, pm string) string {
	switch pm {
	case "uv":
		return "uv sync"
	case "poetry":
		return "poetry update " + p.PackageName
	case "pdm":
		return "pdm update " + p.PackageName
	case "pipenv":
		return "pipenv update " + p.PackageName
	default:
		return p.Command
	}
}

// scanAfterAutofix re-parses the (post-fix) manifests and re-queries the VDB to
// determine which vulnerabilities remain. It routes through the same self-healing
// /v2/cli.sca path as the primary scan (confirmation mode: no reachability,
// snapshot, or persistence) — there is no legacy per-PURL fallback.
func scanAfterAutofix(files []scan.DetectedFile) ([]scan.EnrichedVuln, error) {
	var allPackages []scan.ScopedPackage
	for _, f := range files {
		if f.FileType == scan.FileTypeCycloneDX {
			cdxBom, err := parseCDXForScan(f.Path)
			if err != nil {
				continue
			}
			pkgs := buildPackagesFromCDX(cdxBom.Components, f.RelPath)
			allPackages = append(allPackages, pkgs...)
			continue
		}
		if f.ManifestInfo == nil || !f.Supported {
			continue
		}
		pkgs, err := scan.ParseManifestWithScope(f.Path, f.ManifestInfo.Type)
		if err != nil {
			continue
		}
		for i := range pkgs {
			pkgs[i].SourceFile = f.RelPath
		}
		allPackages = append(allPackages, pkgs...)
	}
	if len(allPackages) == 0 {
		return nil, nil
	}
	return confirmVulnsViaCliSCA(allPackages)
}

func resolvedAutofixFindings(plans []autofix.FixCandidate, after []scan.EnrichedVuln) []*triage.TriageFinding {
	remaining := map[string]bool{}
	for _, ev := range after {
		remaining[autofixFindingKey(ev.CveID, ev.PackageName, ev.Ecosystem)] = true
	}
	var findings []*triage.TriageFinding
	for _, p := range plans {
		if p.Skipped || p.TargetVer == "" {
			continue
		}
		for _, id := range p.CveIDs {
			if remaining[autofixFindingKey(id, p.PackageName, p.Ecosystem)] {
				continue
			}
			findings = append(findings, &triage.TriageFinding{
				CVEID:         id,
				Package:       p.PackageName,
				Ecosystem:     p.Ecosystem,
				InstalledVer:  p.CurrentVer,
				FixedVer:      p.TargetVer,
				Status:        "not_affected",
				Justification: "vulnerable_code_not_present",
			})
		}
	}
	return findings
}

func autofixFindingKey(cveID, packageName, ecosystem string) string {
	return strings.ToLower(cveID) + "::" + strings.ToLower(packageName) + "::" + strings.ToLower(ecosystem)
}

func writeAutofixVEX(root string, findings []*triage.TriageFinding) (string, error) {
	if len(findings) == 0 {
		return "", nil
	}
	data, err := triage.GenerateOpenVEX(findings, triage.OpenVEXOptions{Tooling: "vulnetix-cli sca-autofix"})
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, ".vulnetix", "vex-autofix.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func postAutofixVEXToSnapshot(snapshotUuid string, persisted []vdb.CliFindingResult, findings []*triage.TriageFinding, plans []autofix.FixCandidate, counts autofix.ProofCounts, gitCtx *gitctx.GitContext, sysInfo *gitctx.SystemInfo, rootPath string, packages []scan.ScopedPackage, w io.Writer) {
	if snapshotUuid == "" || len(findings) == 0 || isUnauthenticatedScan() {
		return
	}
	if w == nil {
		w = os.Stderr
	}
	client := newCliClient()
	if client == nil {
		return
	}

	byExact := map[string]vdb.CliFindingResult{}
	byPackage := map[string]vdb.CliFindingResult{}
	for _, f := range persisted {
		if f.FindingID == "" || f.PackageName == "" {
			continue
		}
		byPackage[autofixPersistedKey(f.FindingID, f.PackageName, "")] = f
		if f.PackageVersion != "" {
			byExact[autofixPersistedKey(f.FindingID, f.PackageName, f.PackageVersion)] = f
		}
	}

	planByFinding := map[string]autofix.FixCandidate{}
	for _, p := range plans {
		for _, id := range p.CveIDs {
			planByFinding[autofixFindingKey(id, p.PackageName, p.Ecosystem)] = p
		}
	}

	rows := make([]vdb.CliReachabilityPayload, 0, len(findings))
	for _, f := range findings {
		if f == nil || f.CVEID == "" || f.Package == "" {
			continue
		}
		persistedFinding := byExact[autofixPersistedKey(f.CVEID, f.Package, f.InstalledVer)]
		if persistedFinding.FindingUuid == "" {
			persistedFinding = byPackage[autofixPersistedKey(f.CVEID, f.Package, "")]
		}
		plan := planByFinding[autofixFindingKey(f.CVEID, f.Package, f.Ecosystem)]
		evidence, _ := json.Marshal(autofixEvidencePayload(f, plan, counts))
		rows = append(rows, vdb.CliReachabilityPayload{
			CveID:                  f.CVEID,
			FindingUuid:            persistedFinding.FindingUuid,
			PackageName:            f.Package,
			PackageVersion:         f.InstalledVer,
			Ecosystem:              f.Ecosystem,
			Source:                 "SYMBOL_FALLBACK",
			Verdict:                "UNREACHABLE",
			EvidenceJSON:           string(evidence),
			MemoryVexStatus:        "not_affected",
			MemoryVexJustification: "vulnerable_code_not_present",
			MemoryVexAction:        "fixed by vulnetix sca --sca-autofix",
			FixedVersion:           f.FixedVer,
		})
	}
	if len(rows) == 0 {
		return
	}

	env := buildCliEnv(gitCtx, sysInfo)
	enrichCliEnvForSCA(&env, rootPath, packages, gitCtx)
	resp, err := client.CliSCAReachability(env, vdb.CliSCAReachabilityRequest{
		IngestionSnapshotUuid: snapshotUuid,
		Results:               rows,
	})
	if err != nil {
		fmt.Fprintf(w, "  warning: autofix VEX publish failed: %v\n", err)
		return
	}
	if resp != nil && resp.Data.VEXUrl != "" {
		fmt.Fprintf(w, "  autofix VEX published: %s\n", resp.Data.VEXUrl)
	}
}

func autofixEvidencePayload(f *triage.TriageFinding, plan autofix.FixCandidate, counts autofix.ProofCounts) map[string]any {
	payload := map[string]any{
		"source":        "vulnetix-cli sca-autofix",
		"installed":     "",
		"fixed_version": "",
		"proof_of_work": map[string]int{
			"direct":                    counts.Direct,
			"transitive_parent_update":  counts.TransitiveParentUpdate,
			"transitive_parent_upgrade": counts.TransitiveParentUpgrade,
			"transitive_override":       counts.TransitiveOverride,
			"unresolved_deep_chains":    counts.UnresolvedDeepChains,
		},
	}
	if f != nil {
		payload["installed"] = f.InstalledVer
		payload["fixed_version"] = f.FixedVer
	}
	if plan.PackageName != "" {
		payload["package"] = plan.PackageName
		payload["ecosystem"] = plan.Ecosystem
		payload["method"] = string(plan.Method)
		payload["command"] = plan.Command
		payload["source_file"] = plan.SourceFile
		payload["target_version"] = plan.TargetVer
		payload["parent_name"] = plan.ParentName
		payload["parent_range"] = plan.ParentRange
		payload["parent_target"] = plan.ParentTarget
		payload["reason"] = plan.Reason
	}
	return payload
}

// skippedPlansWithNoSafeVersion returns the subset of plans that were skipped
// because no vulnerability-free Safe-Harbour version exists.
func skippedPlansWithNoSafeVersion(plans []autofix.FixCandidate) []autofix.FixCandidate {
	var out []autofix.FixCandidate
	for _, p := range plans {
		if p.Skipped && strings.Contains(p.SkipReason, "no Safe-Harbour") {
			out = append(out, p)
		}
	}
	return out
}

// writeStaticAnalysisVEX writes an OpenVEX document recording triage state
// changes for static-analysis findings (sast / secrets / iac / container).
// Static-analysis scans emit SARIF + OpenVEX only — never a CycloneDX BOM — so
// finding transitions (fixed, regressed/under-investigation) are attested here
// rather than in a CDX VEX section. Returns "" when there is nothing to attest.
func writeStaticAnalysisVEX(root string, changes []memory.StateChange) (string, error) {
	if len(changes) == 0 {
		return "", nil
	}
	findings := make([]*triage.TriageFinding, 0, len(changes))
	for i := range changes {
		sc := changes[i]
		// Prefer the human-readable rule ID (carried as the first alias) over
		// the internal fingerprint for the OpenVEX vulnerability identifier.
		name := sc.CveID
		if len(sc.Finding.Aliases) > 0 && sc.Finding.Aliases[0] != "" {
			name = sc.Finding.Aliases[0]
		}
		tf := &triage.TriageFinding{
			CVEID:    name,
			Status:   sc.NewStatus,
			Severity: sc.Finding.Severity,
		}
		if sc.NewStatus == "fixed" && sc.Comment != "" {
			tf.ActionResponse = sc.Comment
		}
		findings = append(findings, tf)
	}
	data, err := triage.GenerateOpenVEX(findings, triage.OpenVEXOptions{Tooling: "vulnetix-cli static-analysis"})
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, ".vulnetix", "vex.openvex.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// writeRiskAcceptedVEX generates an OpenVEX document for packages that could
// not be fixed because every available version has vulnerabilities. The
// document records a risk-accepted decision and is written to
// .vulnetix/vex-risk-accepted.json.
func writeRiskAcceptedVEX(root string, skipped []autofix.FixCandidate, enrichedVulns []scan.EnrichedVuln) (string, error) {
	if len(skipped) == 0 {
		return "", nil
	}

	skipSet := map[string]bool{}
	for _, p := range skipped {
		skipSet[strings.ToLower(p.PackageName+"::"+p.Ecosystem)] = true
	}

	var findings []*triage.TriageFinding
	seen := map[string]bool{}
	for i := range enrichedVulns {
		v := &enrichedVulns[i]
		if !skipSet[strings.ToLower(v.PackageName+"::"+v.Ecosystem)] {
			continue
		}
		key := strings.ToLower(v.CveID + "::" + v.PackageName)
		if seen[key] {
			continue
		}
		seen[key] = true
		findings = append(findings, &triage.TriageFinding{
			CVEID:          v.CveID,
			Package:        v.PackageName,
			Ecosystem:      v.Ecosystem,
			InstalledVer:   v.PackageVer,
			Status:         "affected",
			ActionResponse: "risk-accepted: no vulnerability-free version available under safest strategy",
		})
	}
	if len(findings) == 0 {
		return "", nil
	}

	data, err := triage.GenerateOpenVEX(findings, triage.OpenVEXOptions{Tooling: "vulnetix-cli sca-autofix safest"})
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, ".vulnetix", "vex-risk-accepted.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// postRiskAcceptedVEXToSnapshot posts risk-acceptance VEX entries for packages
// that have no vulnerability-free Safe-Harbour version. Mirrors
// postAutofixVEXToSnapshot but uses Verdict "AFFECTED" and VEX status
// "affected" to record that the team is aware and has accepted the risk.
func postRiskAcceptedVEXToSnapshot(snapshotUuid string, persisted []vdb.CliFindingResult, skipped []autofix.FixCandidate, enrichedVulns []scan.EnrichedVuln, counts autofix.ProofCounts, gitCtx *gitctx.GitContext, sysInfo *gitctx.SystemInfo, rootPath string, packages []scan.ScopedPackage, w io.Writer) {
	if snapshotUuid == "" || len(skipped) == 0 || isUnauthenticatedScan() {
		return
	}
	if w == nil {
		w = os.Stderr
	}
	client := newCliClient()
	if client == nil {
		return
	}

	byExact := map[string]vdb.CliFindingResult{}
	byPackage := map[string]vdb.CliFindingResult{}
	for _, f := range persisted {
		if f.FindingID == "" || f.PackageName == "" {
			continue
		}
		byPackage[autofixPersistedKey(f.FindingID, f.PackageName, "")] = f
		if f.PackageVersion != "" {
			byExact[autofixPersistedKey(f.FindingID, f.PackageName, f.PackageVersion)] = f
		}
	}

	skipSet := map[string]bool{}
	planByFinding := map[string]autofix.FixCandidate{}
	for _, p := range skipped {
		skipSet[strings.ToLower(p.PackageName+"::"+p.Ecosystem)] = true
		for _, id := range p.CveIDs {
			planByFinding[autofixFindingKey(id, p.PackageName, p.Ecosystem)] = p
		}
	}

	seen := map[string]bool{}
	var rows []vdb.CliReachabilityPayload
	for i := range enrichedVulns {
		v := &enrichedVulns[i]
		if !skipSet[strings.ToLower(v.PackageName+"::"+v.Ecosystem)] {
			continue
		}
		key := strings.ToLower(v.CveID + "::" + v.PackageName)
		if seen[key] {
			continue
		}
		seen[key] = true

		pf := byExact[autofixPersistedKey(v.CveID, v.PackageName, v.PackageVer)]
		if pf.FindingUuid == "" {
			pf = byPackage[autofixPersistedKey(v.CveID, v.PackageName, "")]
		}
		plan := planByFinding[autofixFindingKey(v.CveID, v.PackageName, v.Ecosystem)]
		f := &triage.TriageFinding{
			CVEID:        v.CveID,
			Package:      v.PackageName,
			Ecosystem:    v.Ecosystem,
			InstalledVer: v.PackageVer,
		}
		evidence, _ := json.Marshal(autofixEvidencePayload(f, plan, counts))
		rows = append(rows, vdb.CliReachabilityPayload{
			CveID:                  v.CveID,
			FindingUuid:            pf.FindingUuid,
			PackageName:            v.PackageName,
			PackageVersion:         v.PackageVer,
			Ecosystem:              v.Ecosystem,
			Source:                 "SAFE_HARBOUR_ANALYSIS",
			Verdict:                "AFFECTED",
			EvidenceJSON:           string(evidence),
			MemoryVexStatus:        "affected",
			MemoryVexJustification: "",
			MemoryVexAction:        "risk-accepted: no vulnerability-free version available under safest strategy",
		})
	}
	if len(rows) == 0 {
		return
	}

	env := buildCliEnv(gitCtx, sysInfo)
	enrichCliEnvForSCA(&env, rootPath, packages, gitCtx)
	resp, err := client.CliSCAReachability(env, vdb.CliSCAReachabilityRequest{
		IngestionSnapshotUuid: snapshotUuid,
		Results:               rows,
	})
	if err != nil {
		fmt.Fprintf(w, "  warning: risk-accepted VEX publish failed: %v\n", err)
		return
	}
	if resp != nil && resp.Data.VEXUrl != "" {
		fmt.Fprintf(w, "  risk-accepted VEX published: %s\n", resp.Data.VEXUrl)
	}
}

func autofixPersistedKey(cveID, packageName, version string) string {
	return strings.ToLower(cveID) + "::" + strings.ToLower(packageName) + "::" + version
}

func recordAutofixMemoryEvents(mem *memory.Memory, findings []*triage.TriageFinding) {
	if mem == nil || len(findings) == 0 {
		return
	}
	if mem.Findings == nil {
		mem.Findings = map[string]memory.FindingRecord{}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, f := range findings {
		if f == nil || f.CVEID == "" {
			continue
		}
		rec := mem.Findings[f.CVEID]
		if rec.Package == "" {
			rec.Package = f.Package
		}
		if rec.Ecosystem == "" {
			rec.Ecosystem = f.Ecosystem
		}
		rec.Status = "fixed"
		rec.Source = "vulnetix-sca"
		rec.Tool = memory.ToolSCA
		rec.Justification = "vulnerable_code_not_present"
		rec.ActionResponse = "fixed by vulnetix sca --sca-autofix"
		if rec.Versions == nil {
			rec.Versions = &memory.VersionInfo{}
		}
		if rec.Versions.Current == "" {
			rec.Versions.Current = f.InstalledVer
		}
		rec.Versions.FixedIn = f.FixedVer
		rec.Versions.FixSource = "sca-autofix"
		if rec.Remediation == nil {
			rec.Remediation = &memory.RemediationData{}
		}
		rec.Remediation.FixAvailability = "available"
		rec.Remediation.FixVersion = f.FixedVer

		detail := fmt.Sprintf("%s %s -> %s via vulnetix sca --sca-autofix", f.Package, f.InstalledVer, f.FixedVer)
		if !hasAutofixHistory(rec, detail) {
			rec.History = append(rec.History, memory.HistoryEntry{
				Date:   now,
				Event:  "autofix-applied",
				Detail: detail,
			})
		}
		mem.Findings[f.CVEID] = rec
	}
}

func hasAutofixHistory(rec memory.FindingRecord, detail string) bool {
	for _, h := range rec.History {
		if h.Event == "autofix-applied" && h.Detail == detail {
			return true
		}
	}
	return false
}

// printScanArtifacts prints the artefact links (BOM / Memory / SARIF / Rules and
// ingestion snapshot URLs) at the very bottom of the scan output, after all
// analysis tables. Each line is gated on a non-empty value. scaSnapshotURL is
// the /v2/cli.sca snapshot; snapshots carries one link per SARIF kind
// (SAST/Secrets/IaC/Containers) submitted this scan.
func printScanArtifacts(sbomPath, sarifPath, vulnetixDir, rulesPath, scaSnapshotURL string, snapshots []snapshotLink) {
	t := display.NewTerminal()
	if sbomPath != "" {
		fmt.Fprintf(os.Stdout, "  %s BOM:      %s\n", display.CheckMark(t), sbomPath)
	}
	fmt.Fprintf(os.Stdout, "  %s Memory:   %s\n", display.CheckMark(t), filepath.Join(vulnetixDir, memory.FileName))
	if sarifPath != "" {
		fmt.Fprintf(os.Stdout, "  %s SARIF:    %s\n", display.CheckMark(t), sarifPath)
	}
	if rulesPath != "" {
		fmt.Fprintf(os.Stdout, "  %s Rules:    %s\n", display.CheckMark(t), rulesPath)
	}
	if scaSnapshotURL != "" {
		fmt.Fprintf(os.Stdout, "  %s Snapshot: %s\n", display.CheckMark(t), scaSnapshotURL)
	}
	for _, s := range snapshots {
		if s.URL == "" || s.URL == scaSnapshotURL {
			continue
		}
		fmt.Fprintf(os.Stdout, "  %s %s Snapshot: %s\n", display.CheckMark(t), s.Label, s.URL)
	}
	fmt.Fprintln(os.Stdout)
}

// isUnauthenticatedScan reports whether the scan is running without a real org
// account — i.e. on the shared embedded community credentials (or no creds at
// all). Such scans still get vuln enrichment, but the server never persists a
// snapshot for them, so the CLI skips the persist-only calls + snapshot output
// and nudges the user to claim their own free Community Plan key.
func isUnauthenticatedScan() bool {
	return vdbCreds == nil || auth.IsCommunity(vdbCreds)
}

// printCommunitySignupReminder tells unauthenticated users why no snapshot was
// produced and how to get one (a free Community Plan account with its own
// dedicated quota, instead of the shared embedded credentials).
func printCommunitySignupReminder() {
	fmt.Fprintln(os.Stderr, "  ℹ Snapshots are skipped for unauthenticated scans.")
	fmt.Fprintln(os.Stderr, "    Get a free Community Plan API key (your own dedicated quota) at")
	fmt.Fprintln(os.Stderr, "    https://www.vulnetix.com/vdb-register, then run 'vulnetix auth login'.")
	fmt.Fprintln(os.Stderr)
}

// printSnapshotsToStderr echoes SARIF ingestion snapshot links to stderr, used
// by the machine-readable output modes that skip the pretty artefact summary.
func printSnapshotsToStderr(snapshots []snapshotLink) {
	if silent {
		return
	}
	for _, s := range snapshots {
		if s.URL == "" {
			continue
		}
		fmt.Fprintf(os.Stderr, "%s snapshot: %s\n", s.Label, s.URL)
	}
}

// anyReachabilityAssessed returns true if any vuln has ReachabilityAssessed set.
func anyReachabilityAssessed(vulns []scan.EnrichedVuln) bool {
	for _, v := range vulns {
		if v.ReachabilityAssessed {
			return true
		}
	}
	return false
}

// countReachability returns (assessed, reachable, notReachable, notAssessable)
// across all vulns. A vuln is "assessed" when ReachabilityAssessed is true and
// the verdict is reachable or unreachable. Unassessed counts as notAssessable.
func countReachability(vulns []scan.EnrichedVuln) (assessed, reachable, notReachable, notAssessable int) {
	for _, v := range vulns {
		if !v.ReachabilityAssessed {
			notAssessable++
			continue
		}
		assessed++
		switch v.Reachability {
		case "direct", "transitive", "semantic":
			reachable++
		case "unreachable":
			notReachable++
		default:
			notAssessable++
		}
	}
	return
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

	// Allow pointing the CLI at an alternate VDB API (a local mock for
	// performance/parity testing, or a self-hosted deployment) without
	// recompiling. Empty/unset keeps the production default.
	if u := strings.TrimSpace(os.Getenv("VULNETIX_API_URL")); u != "" {
		client.BaseURL = strings.TrimRight(u, "/")
	}

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

// pluralise returns "<n> <word>" with the word pluralised for n
// (e.g. "1 dependency", "2 dependencies"). Do not also print the count
// separately in the same phrase — that double-counts.
func pluralise(word string, n int) string {
	return fmt.Sprintf("%d %s", n, plural(word, n))
}

// plural returns word pluralised for n, with NO count prefix — for phrases
// that already state the number explicitly (e.g. "within the 1 most recent
// releases"). For the count+word form use pluralise.
func plural(word string, n int) string {
	if n == 1 {
		return word
	}
	plurals := map[string]string{
		"vulnerability": "vulnerabilities",
		"dependency":    "dependencies",
		"advisory":      "advisories",
		"library":       "libraries",
		"entry":         "entries",
		"match":         "matches",
	}
	if p, ok := plurals[word]; ok {
		return p
	}
	return word + "s"
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

// writeBOMToFile writes a CycloneDX BOM as JSON to the given path, creating
// directories as needed. The BOM is validated against the canonical CycloneDX
// schema before anything is written: an invalid document fails fast and the
// file on disk is left untouched, so we never persist an SBOM the upload
// pipeline would later reject.
func writeBOMToFile(bom *cdx.BOM, path string) error {
	// Heal known legacy enum classes (e.g. severity "unscored", a stale
	// justification carried forward from an older on-disk SBOM during merge)
	// before validating, so a rescan never fails on values it did not author.
	bom.NormalizeForSchema()
	data, err := bom.MarshalValidatedJSON()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
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
	cmd.Flags().Bool("show-introduced-paths", false, "Show the full chain from manifest to the affected transitive package (npm, Python, Rust, Ruby, PHP, Go). Direct deps are introduced by the manifest itself and omitted.")
	// Deprecated alias retained for backward compatibility — the documented
	// name is --show-introduced-paths.
	cmd.Flags().Bool("paths", false, "Deprecated alias for --show-introduced-paths")
	if hide := cmd.Flags().MarkHidden("paths"); hide != nil {
		// non-fatal if rename hasn't propagated everywhere
		_ = hide
	}
	cmd.Flags().Bool("no-exploits", false, "Suppress detailed exploit intelligence section")
	cmd.Flags().Bool("no-remediation", false, "Suppress detailed remediation section")
	cmd.Flags().String("severity", "", "Exit with code 1 if any vulnerability meets or exceeds this severity (low, medium, high, critical). Severity is coerced from all available scoring sources (CVSS, EPSS, Coalition ESS, SSVC).")
	cmd.Flags().Bool("block-malware", false, "Exit with code 1 when any dependency is a known malicious package.")
	cmd.Flags().Bool("no-malscan", false, "Skip the in-process malscan-engine pass over local dependency install dirs.")
	cmd.Flags().Bool("block-eol", false, "Exit with code 1 when a runtime or package dependency is end-of-life. Runtimes: Go, Node.js, Python, Ruby. Package-level checks activate when VDB has EOL data (404s are silently skipped).")
	cmd.Flags().Bool("block-unpinned", false, "Exit with code 1 when any direct dependency uses a version range (^, ~, >=) instead of an exact pin.")
	cmd.Flags().String("exploits", "", "Exit with code 1 when exploit maturity reaches the threshold: poc (any public exploit), active (CISA/EU KEV / actively exploited), weaponized (in-the-wild only).")
	cmd.Flags().Bool("results-only", false, "Only output when findings exist; completely silent when the scan is clean.")
	cmd.Flags().Bool("show-detected", false, "Show the 'Detected files:' listing and 'Analysing N file(s)…' progress banner.")
	cmd.Flags().Bool("show-all-manifests", false, "Include rows in the SCA table for manifests that have no vulnerabilities.")
	cmd.Flags().Int("version-lag", 0, "Exit with code 1 when any dependency is within the N most recently published versions of that package (0 = disabled).")
	cmd.Flags().Int("cooldown", 0, "Exit with code 1 when any dependency version was published within the last N days (0 = disabled, best-effort).")
	cmd.Flags().Bool("sca-autofix", false, "Apply validated SCA fixes with the project package manager, then rescan to confirm")
	cmd.Flags().String("sca-autofix-strategy", "stable", "SCA autofix target strategy: latest, safest, or stable")
	cmd.Flags().String("sca-autofix-manifest", "", "Restrict SCA autofix edits to one manifest file")
	cmd.Flags().Bool("yes", false, "Non-interactive mode for SCA autofix: auto-pick safe defaults and never prompt")
	cmd.Flags().Int("sca-autofix-max-major-bump", 0, "Refuse SCA autofix targets crossing more than N major versions")
	cmd.Flags().Bool("dry-run", false, "Detect files and parse packages locally, check memory, then exit — zero API calls")
	// Secrets-only flags. They are registered on every scan-style subcommand
	// so that `scan --evaluate-secrets --ignore-git` works just as well as
	// `secrets --ignore-git`, but the flags are documented under the
	// secrets subcommand and only meaningfully affect the secrets stage.
	cmd.Flags().StringArray("ignore", nil,
		"Glob pattern (relative to scan root) to skip during the secrets stage; repeatable")
	cmd.Flags().Bool("ignore-git", false,
		"Skip the .git directory during the secrets stage. Default is to scan .git so credentials in past commits are surfaced")
	cmd.Flags().Bool("ignore-binaries", false,
		"Skip binary files during the secrets stage. Default is to extract printable strings and EXIF metadata from binaries")
	cmd.Flags().Bool("git-history", true,
		"When the secrets stage runs, walk git history (newest first) and scan the file contents of every changed path")
	cmd.Flags().Int("git-history-max-commits", 500,
		"Cap the number of commits walked during the git-history secrets stage (0 = no cap)")
	cmd.Flags().Int("git-history-max-files", 5000,
		"Cap the number of file versions extracted from git history (0 = no cap)")
	_ = cmd.Flags().MarkDeprecated("format", "use --output instead")
	_ = cmd.RegisterFlagCompletionFunc("sca-autofix-strategy", cobra.FixedCompletions(
		[]string{"stable", "safest", "latest"}, cobra.ShellCompDirectiveNoFileComp))
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
			// CDX / SPDX SBOM inputs are SCA content (a committed SBOM is not a
			// container/IaC/SAST target). Include them only when SCA is active,
			// so e.g. a `containers` scan of a repo that happens to carry an
			// osv.cdx.json doesn't pull that SBOM's whole package set into the
			// container component list.
			if !noSCA {
				filtered = append(filtered, f)
			}
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

// specializedRuleKinds returns the locked Rego kind-set for a specialized scan
// subcommand, or nil for the generic "scan" command (and "sca", which runs no
// Rego). When non-nil the kinds are authoritative: only rules of these kinds
// run, embedded and externally imported alike (see filterModulesToKinds), so a
// `containers --rule <pack>` scan cannot bleed into the pack's secrets/iac/api
// rules. Container rules are tagged inconsistently across rule sources —
// embedded rules use "oci", community-rules uses "container" — so both are in
// the container scope.
func specializedRuleKinds(cmdName string) []string {
	switch cmdName {
	case "containers":
		return []string{"oci", "container"}
	case "secrets":
		return []string{"secrets"}
	case "iac":
		return []string{"iac"}
	case "sast":
		return []string{"sast"}
	default:
		return nil
	}
}

// filterModulesToKinds keeps only the Rego modules whose declared kind is in the
// allowed set. Unlike filterModulesByKind it does NOT exempt externally imported
// (--rule) packs: a locked specialized subcommand applies its kind scope to
// every rule regardless of origin.
//
// Library/helper modules — those declaring no rule "id" (e.g. a pack's shared
// _lib/docker.rego) — are always retained: the kept rules compile against them,
// and OPA compiles every module together, so dropping a dependency would fail
// the whole evaluation. Libraries produce no findings, so keeping a few extra is
// harmless. Modules without a "kind" field default to "sast" (see extractRegoKind).
func filterModulesToKinds(modules map[string]string, kinds []string) map[string]string {
	if len(kinds) == 0 {
		return modules
	}
	allowed := make(map[string]bool, len(kinds))
	for _, k := range kinds {
		allowed[k] = true
	}
	filtered := make(map[string]string, len(modules))
	for name, src := range modules {
		// Retain shared libraries (no rule id) as compile dependencies.
		if extractRegoID(src) == "" || allowed[extractRegoKind(src)] {
			filtered[name] = src
		}
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
		// Externally imported rules (loaded from --rule repos) bypass the
		// kind filter — the user explicitly asked for them. Embedded
		// default rules live under the "rules/" prefix in the embed.FS.
		if !strings.HasPrefix(name, "rules/") {
			filtered[name] = src
			continue
		}
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
	scanCmd.Flags().Bool("no-aibom", false, "Skip AI Bill of Materials (AIBOM) detection + submission during scan")
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
	scanCmd.Flags().Int("snippet-context", -1, "Surrounding non-empty source lines to capture around each SARIF finding (-1 = dynamic: 3 if span <10 lines else 5; 0 disables)")

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
