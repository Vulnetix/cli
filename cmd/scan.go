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
	"github.com/vulnetix/cli/v3/internal/pipeline"
	"github.com/vulnetix/cli/v3/internal/sast"
	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/internal/scanopts"
	"github.com/vulnetix/cli/v3/internal/testsuite"
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

// orgEOLBuckets maps an end-of-life horizon to a severity. It starts at the same
// defaults the CliQualityGateConfig columns declare, and applyOrgQualityGate
// overwrites it with the org's own mapping when the scan is authenticated.
//
// Package-level for the same reason `verbose` is: the gate that consumes it sits
// behind a thirty-argument positional signature, and threading a thirty-first
// through it would obscure the change rather than clarify it.
var orgEOLBuckets = scan.DefaultEOLSeverityBuckets()

// eolBlockSeverity is the floor at which a graded EOL finding actually FAILS the
// build, as opposed to merely being reported.
//
// It defaults to `critical`, which is the default severity of the `retired`
// bucket — so by default exactly what failed a build before grading existed fails
// it now: components already past their end-of-life date. Everything closer to the
// horizon is reported and does not break anyone's pipeline.
//
// This default is deliberately conservative. Grading arrived with the CLI release,
// not with an org's decision to adopt it, and a release that turns "your runtime
// dies next quarter" into a red build would break CI for every customer who has
// ever passed --block-eol.
var eolBlockSeverity = "critical"

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
		// --dry-run and --list-default-rules are handled inside
		// runScanWithFeatures, so every scan-family command honours them.
		if dryRun, _ := cmd.Flags().GetBool("dry-run"); dryRun {
			for _, freshFlag := range []string{"fresh-exploits", "fresh-advisories", "fresh-vulns"} {
				if v, _ := cmd.Flags().GetBool(freshFlag); v {
					return fmt.Errorf("--%s cannot be used with --dry-run (dry run makes no API calls)", freshFlag)
				}
			}
		}

		// ── --from-memory path (deprecated: use `vulnetix report`) ────────
		// Replaying stored results is not a scan, so `report` owns it. The flags
		// stay as aliases and delegate, with cobra printing the deprecation notice.
		fromMemory, _ := cmd.Flags().GetBool("from-memory")
		if fromMemory {
			freshExploits, _ := cmd.Flags().GetBool("fresh-exploits")
			freshAdvisories, _ := cmd.Flags().GetBool("fresh-advisories")
			freshVulns, _ := cmd.Flags().GetBool("fresh-vulns")
			scanPath, _ := cmd.Flags().GetString("path")
			return renderStoredReport(scanPath, freshExploits, freshAdvisories, freshVulns)
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

		// Capture cryptographic inventory (PQC posture) alongside the scan.
		// Best-effort and authenticated-only; never changes the scan's exit code.
		if noCbom, _ := cmd.Flags().GetBool("no-cbom"); !noCbom {
			scanPath, _ := cmd.Flags().GetString("path")
			if scanPath == "" {
				scanPath = "."
			}
			detectAndUploadCBOM(scanPath, gitctx.Collect(scanPath))
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
	// --list-default-rules is a listing, not a scan. Served here so every command
	// that registers the flag honours it (see cmd/sast_rules.go).
	if handled, err := handleSASTRuleListing(cmd); handled {
		return err
	}

	// One place knows how a scan-family flag becomes an analysis input. What it
	// leaves zero — detected files, the No* feature booleans, LockedKinds,
	// RespectGitignore, git/system context and the seed BOMs — is filled in
	// below, because none of it is decided by flags alone.
	opts, err := scanopts.FromCommand(cmd)
	if err != nil {
		return err
	}

	// Locals for the values this function still reasons about before handing
	// opts to the scan. Everything else stays on opts.
	scanPath := opts.RootPath
	depth := opts.Depth
	suppressTestCode, _ = cmd.Flags().GetBool("suppress-test-code")
	excludes := opts.Excludes
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
	// Already normalised and validated by scanopts.FromCommand.
	severityThreshold := opts.SeverityThreshold

	blockMalware := opts.BlockMalware
	blockEOL := opts.BlockEOL
	if v, _ := cmd.Flags().GetString("block-eol-severity"); v != "" {
		eolBlockSeverity = strings.ToLower(strings.TrimSpace(v))
	}
	blockUnpinned := opts.BlockUnpinned
	exploitThreshold := opts.ExploitThreshold
	resultsOnly := opts.ResultsOnly
	noCIPackageAnalysis, _ := cmd.Flags().GetBool("no-ci-package-analysis")
	noShellPackageAnalysis, _ := cmd.Flags().GetBool("no-shell-package-analysis")
	versionLag := opts.VersionLag
	cooldownDays := opts.CooldownDays
	dryRun := opts.DryRun
	scaAutofix := opts.SCAAutofix
	scaAutofixStrategyRaw, _ := cmd.Flags().GetString("sca-autofix-strategy")
	scaAutofixManifest, _ := cmd.Flags().GetString("sca-autofix-manifest")
	scaAutofixMaxMajorBump, _ := cmd.Flags().GetInt("sca-autofix-max-major-bump")
	yes, _ := cmd.Flags().GetBool("yes")
	pathExplicit := cmd.Flags().Changed("path")

	// gitignore respect: the SAST-family walks (sast/secrets/containers/iac,
	// and the generic scan's SAST engine) honour .gitignore by default. sca is
	// exempt — dependency manifests routinely live in gitignored install dirs —
	// and so the shared manifest walk only prunes .gitignore for the standalone
	// containers/iac commands (where SCA is not consuming its output). Users opt
	// back in with --include-ignored (generic) or --<mode>-include-ignored.
	includeIgnored := includeIgnoredForScan(cmd)
	respectGitignoreSAST := !includeIgnored
	respectGitignoreManifest := !includeIgnored && (cmd.Name() == "containers" || cmd.Name() == "iac")

	// Org quality-gate enforcement override. Applied after all nine control
	// flags are read but BEFORE any is consumed (sca-autofix strategy parsing
	// below, runLocalScan, and the gate options). For an authenticated org with
	// a quality-gate policy, a set org value overwrites the local in place —
	// org policy always wins, even over an explicitly-passed flag. Unauthenticated
	// / community scans and orgs without a policy leave these values untouched.
	applyOrgQualityGate(cmd, qualityGateOverridePointers{
		blockEol:               &blockEOL,
		eolBuckets:             &orgEOLBuckets,
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

	// The exploit threshold was normalised and validated by
	// scanopts.FromCommand, but org quality-gate policy may have replaced it
	// with a value the org set, so re-validate what is about to be used.
	exploitThreshold, err = scanopts.NormaliseExploits(exploitThreshold)
	if err != nil {
		return err
	}
	severityThreshold, err = scanopts.NormaliseSeverity(severityThreshold)
	if err != nil {
		return err
	}

	// SAST flags.
	disableDefaultRules := opts.DisableDefaultRules
	ruleRefs := opts.RuleRefs
	ruleRegistry := opts.RuleRegistry
	ruleID := opts.RuleID
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

	// ── Dry run: local discovery only, zero API calls ──────────────────
	// Handled here rather than in scanCmd.RunE so `sca --dry-run`,
	// `secrets --dry-run` and the rest honour the flag they advertise instead of
	// silently running a live scan. It must precede the malscan pass, which
	// uploads its findings when authenticated.
	//
	// --sca-autofix --dry-run is different: it means "show me the fix plan", which
	// needs the SCA round-trip, so that combination falls through to the autofix
	// proposal path inside runLocalScan.
	if dryRun && !scaAutofix {
		return runDryScan(dryScanOptions{
			RootPath:          scanPath,
			Depth:             depth,
			Excludes:          excludes,
			SeverityThreshold: severityThreshold,
			Scope: scanFeatureScope{
				NoSAST:       noSAST,
				NoSCA:        noSCA,
				NoLicenses:   noLicenses,
				NoSecrets:    noSecrets,
				NoContainers: noContainers,
				NoIAC:        noIAC,
			},
			RespectGitignoreManifest: respectGitignoreManifest,
			RuleRefs:                 ruleRefs,
			RuleRegistry:             ruleRegistry,
			DisableDefaultRules:      disableDefaultRules,
			LockedKinds:              lockedKinds,
		})
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
		RootPath:         scanPath,
		MaxDepth:         depth,
		Excludes:         excludes,
		RespectGitignore: respectGitignoreManifest,
	})
	if err != nil {
		return fmt.Errorf("failed to scan directory: %w", err)
	}

	analytics.TrackScan("sbom", len(files))

	// Surface private/custom package registries declared in .npmrc / .yarnrc /
	// settings.gradle as a supply-chain signal (informational; never gates).
	if endpoints := scan.SummarizeRegistryConfigs(files); len(endpoints) > 0 {
		var privates []scan.RegistryEndpoint
		for _, e := range endpoints {
			if e.Private {
				privates = append(privates, e)
			}
		}
		if len(privates) > 0 && !resultsOnly {
			fmt.Fprintf(os.Stderr, "Registry config: %d private/custom registry endpoint(s) declared:\n", len(privates))
			for _, e := range privates {
				scopeNote := ""
				if e.Scope != "" {
					scopeNote = " (" + e.Scope + ")"
				}
				fmt.Fprintf(os.Stderr, "  %s%s → %s [%s]\n", e.Ecosystem, scopeNote, e.URL, e.Source)
			}
		}
	}

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
			// SPDX is an input format like CycloneDX: its packages are scanned,
			// not merely listed. Only a document whose packages carry purls has
			// anything to match.
			spdxComponents, spdxErr := parseSPDXForScan(f.Path)
			if !resultsOnly && showDetectedForRun {
				if spdxErr == nil {
					fmt.Fprintf(os.Stderr, "  %-40s spdx        v%-8s (%d pkg)\n", f.RelPath, f.SBOMVersion, len(spdxComponents))
				} else {
					fmt.Fprintf(os.Stderr, "  %-40s spdx        v%-9s\n", f.RelPath, f.SBOMVersion)
				}
			}
			if spdxErr == nil && len(spdxComponents) > 0 {
				f.Supported = true
				supportedFiles = append(supportedFiles, f)
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
	supportedFiles = filterCommandPackageFiles(supportedFiles, noCIPackageAnalysis, noShellPackageAnalysis)
	if len(supportedFiles) == 0 {
		sastFamilyEnabled := !noSAST || !noSecrets || !noContainers || !noIAC
		if !sastFamilyEnabled {
			fmt.Fprintln(os.Stderr, "\nNo supported manifest files found for scanning.")
			return mergeMalscanBreach(nil, malscanBreach)
		}
	}

	// ── 5. Collect host environment ─────────────────────────────────────
	sysInfo := gitctx.CollectSystemInfo()

	// ── 6. Run local scan ──────────────────────────────────────────────
	// Everything the flags alone decided is already on opts from
	// scanopts.FromCommand. What follows is the rest: detection results,
	// collected context, the feature booleans, and the gate values as org
	// policy may have rewritten them since.
	opts.Files = supportedFiles
	opts.GitCtx = gitCtx
	opts.SysInfo = sysInfo
	opts.SeedBOM = seedBOM
	opts.VulnetixSeedBOM = vulnetixSeedBOM

	opts.NoLicenses = noLicenses
	opts.NoSASTRules = noSAST
	opts.NoSCA = noSCA
	opts.NoSecrets = noSecrets
	opts.NoContainers = noContainers
	opts.NoIAC = noIAC

	opts.LockedKinds = lockedKinds
	opts.RespectGitignore = respectGitignoreSAST

	// Re-assigned rather than assumed: applyOrgQualityGate rewrites these in
	// place, and org policy wins even over an explicitly passed flag.
	opts.SeverityThreshold = severityThreshold
	opts.ExploitThreshold = exploitThreshold
	opts.BlockMalware = blockMalware
	opts.BlockEOL = blockEOL
	opts.BlockUnpinned = blockUnpinned
	opts.VersionLag = versionLag
	opts.CooldownDays = cooldownDays
	// scaAutofix is cleared when SCA is disabled, so it cannot be taken from
	// the flag value either.
	opts.SCAAutofix = scaAutofix
	opts.SCAAutofixOpts = autofix.Options{
		Strategy:     scaAutofixStrategy,
		MaxMajorBump: scaAutofixMaxMajorBump,
		Manifest:     scaAutofixManifest,
		Yes:          yes,
		PathExplicit: pathExplicit,
	}

	// Single-rule mode (--rule-id) forces the feature booleans above, and the
	// scanPath default is applied after parsing, so take both from the locals.
	opts.RootPath = scanPath

	scanErr := runLocalScan(
		ctx,
		opts,
		outCfg,
		// The scan is one seven-step progress activity on stderr, exactly as
		// before; the reporter is now constructed here rather than inside the
		// analysis, so the same analysis can report to a language-server client
		// instead.
		pipeline.NewTerminalReporter("Scan", 7, silent, noProgress),
	)

	return mergeMalscanBreach(scanErr, malscanBreach)
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
// The analysis inputs arrive as a single pipeline.Options rather than the 40
// positional parameters this function used to take. outCfg stays separate
// because it is presentation, not analysis: it describes where this process
// writes CycloneDX and SARIF, which is meaningless to a language server that
// returns findings over JSON-RPC. rep is likewise the caller's choice of
// progress sink.
func runLocalScan(
	ctx context.Context,
	opts pipeline.Options,
	outCfg *outputConfig,
	rep pipeline.Reporter,
) (retErr error) {
	// Unpacked into the local names the body below already uses. The body is
	// deliberately untouched by this extraction, so the change is reviewable as
	// "signature only" and the behaviour is provably identical.
	files := opts.Files
	rootPath := opts.RootPath
	depth := opts.Depth
	excludes := opts.Excludes
	noProgress := opts.NoProgress
	showPaths := opts.ShowPaths
	noExploits := opts.NoExploits
	noRemediation := opts.NoRemediation
	noLicenses := opts.NoLicenses
	severityThreshold := opts.SeverityThreshold
	blockMalware := opts.BlockMalware
	blockEOL := opts.BlockEOL
	blockUnpinned := opts.BlockUnpinned
	exploitThreshold := opts.ExploitThreshold
	resultsOnly := opts.ResultsOnly
	versionLag := opts.VersionLag
	cooldownDays := opts.CooldownDays
	noSASTRules := opts.NoSASTRules
	noSCA := opts.NoSCA
	noSecrets := opts.NoSecrets
	noContainers := opts.NoContainers
	noIAC := opts.NoIAC
	disableDefaultRules := opts.DisableDefaultRules
	ruleRefs := opts.RuleRefs
	ruleRegistry := opts.RuleRegistry
	ruleID := opts.RuleID
	lockedKinds := opts.LockedKinds
	seedBOM := opts.SeedBOM
	vulnetixSeedBOM := opts.VulnetixSeedBOM
	gitCtx := opts.GitCtx
	sysInfo := opts.SysInfo
	snippetContext := opts.SnippetContext
	dryRun := opts.DryRun
	scaAutofix := opts.SCAAutofix
	scaAutofixOpts := opts.SCAAutofixOpts
	autofixResolved := opts.AutofixResolved
	ignoreGlobs := opts.IgnoreGlobs
	ignoreGit := opts.IgnoreGit
	ignoreBinaries := opts.IgnoreBinaries
	gitHistory := opts.GitHistory
	gitHistoryMaxCommits := opts.GitHistoryMaxCommits
	gitHistoryMaxFiles := opts.GitHistoryMaxFiles
	respectGitignore := opts.RespectGitignore
	licensePolicy := LicensePolicyFlags{
		Mode:      opts.License.Mode,
		AllowCSV:  opts.License.AllowCSV,
		AllowFile: opts.License.AllowFile,
	}

	progressStderr := rep.Writer()
	rep.Stage(fmt.Sprintf("Parsing %d detected file(s)", len(files)))
	defer func() {
		// Complete and Fail are finish-once, so a path that already finished
		// the run (autofix dry run, autofix applied, the normal tail) wins and
		// this deferred call is a no-op.
		if retErr != nil {
			rep.Fail("failed")
			return
		}
		rep.Complete("complete")
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
	// Reset per run so a second invocation in the same process cannot attach its
	// binaries to the previous scan's snapshot.
	lastContainerSnapshotUuid = ""

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
	iacOnly := noSASTRules && noSCA && noSecrets && noContainers && !noIAC
	secretsOnly := noSASTRules && noSCA && !noSecrets && noContainers && noIAC
	switch {
	case containerOnly:
		analysisLabel = "Container"
		analysisTitle = "Container Analysis"
		sarifFileName = "containers.sarif"
		bomToolName = "vulnetix-containers"
	case iacOnly:
		analysisLabel = "IaC"
		analysisTitle = "IaC Analysis"
	case secretsOnly:
		analysisLabel = "Secrets"
		analysisTitle = "Secrets Analysis"
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
			// SBOM input files (CycloneDX or SPDX): extract components as packages.
			if f.FileType == scan.FileTypeCycloneDX || f.FileType == scan.FileTypeSPDX {
				components, err := sbomComponentsForScan(f)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  %-40s parse error: %v\n", f.RelPath, err)
					continue
				}
				pkgs := buildPackagesFromCDX(components, f.RelPath)
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
			// Build-or-lock gate (all ecosystems): an unpinned manifest with no
			// sibling lock must resolve its dependencies from the installed
			// environment, or the scan stops. A confident manifest that can't be
			// resolved is a fatal error (build the app or generate a lock file); a
			// tentatively-detected file (e.g. a bare-name list) that can't be
			// confirmed against installed packages is silently disregarded.
			confident := f.ManifestInfo.Confidence != scan.ConfidenceTentative
			resolved, dropFile, gerr := scan.ApplyBuildOrLockGate(
				f.ManifestInfo.Ecosystem, f.ManifestInfo.Type, f.Path, f.RelPath, confident, pkgs)
			if gerr != nil {
				if !dropFile {
					return gerr
				}
				continue // tentative + unconfirmed → not a real manifest
			}
			pkgs = resolved

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
		rep.Update(1, fmt.Sprintf("Parsed %d package(s)", len(allPackages)))

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
		rep.Stage("Building dependency graph")
		scan.PopulateInstalledEdges(manifestGroups, rootPath)

		if len(allPackages) > 0 {
			rep.Stage(fmt.Sprintf("Resolving package licenses for %d package(s)", len(allPackages)))
			licensedPackages = license.DetectLicenses(allPackages, manifestGroups)
			for _, lp := range licensedPackages {
				if lp.LicenseSpdxID != "" && lp.LicenseSpdxID != "UNKNOWN" {
					licenseByKey[lp.PackageName+"@"+lp.PackageVersion] = lp.LicenseSpdxID
				}
			}
		}
		rep.Update(2, "Prepared dependency metadata")

		// Container-only scans also resolve their parsed components (base images
		// + RUN-installed OS/lang packages) against the VDB so the same CVE data
		// other scanners surface shows up here too. This reuses the SCA path but
		// labels the snapshot as containers and treats an unavailable API as
		// non-fatal (the rego container rules still run).
		//
		// The package count gates both branches. A round-trip carrying an empty
		// PURL list has nothing to ask about and can only fail, and its failure is
		// reported as "check credentials, config, and network connectivity" — so a
		// project whose manifests declare no dependencies used to exit 1 blaming
		// the user's setup for a result that is simply clean.
		runSCAQuery := len(allPackages) > 0 && (!noSCA || containerOnly)
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
				Reachability: opts.Reachability,
			}
			scaToolName := ""
			if containerOnly {
				scaToolName = "vulnetix-containers"
			}
			rep.Stage(fmt.Sprintf("Querying VDB for %d package(s)", countUniquePackages(allPackages)))
			apiServed, apiVulns, apiEnriched, apiInsights, apiSnapshotUuid, apiSnapshotURL, apiPersistedFindings := tryCliSCA(allPackages, manifestGroups, licenseByKey, gitCtx, sysInfo, rootPath, scaToolName, gateOpts, progressStderr)
			if apiServed {
				allVulns = apiVulns
				scaEnrichedFromAPI = apiEnriched
				scaInsights = apiInsights
				scaSnapshotUuid = apiSnapshotUuid
				scaSnapshotURL = apiSnapshotURL
				scaPersistedFindings = apiPersistedFindings
				rep.Update(3, fmt.Sprintf("VDB returned %d finding(s)", len(allVulns)))
			} else if containerOnly {
				// Container scans degrade gracefully: the misconfiguration rego
				// rules still run and write SARIF, even with no VDB connectivity.
				rep.Update(3, fmt.Sprintf("Parsed %d container component(s); VDB lookup unavailable", len(allPackages)))
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
			rep.Update(3, fmt.Sprintf("Parsed %d container component(s)", len(allPackages)))
		}
	} else {
		rep.Update(3, "Skipped SCA package vulnerability lookup")
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
		rep.Update(4, "Skipped SCA vulnerability enrichment")
	} else {
		rep.Update(4, fmt.Sprintf("Received %d enriched finding(s)", len(enrichedVulns)))
	}

	// Drop SCA vulns covered by an active suppression ("ignore") rule before any
	// downstream use (autofix, VEX, BOM ratings, summary, persistence).
	if !noSCA {
		if set := scanSuppressionSetLoad(rootPath, gitCtx); set != nil && !set.Empty() {
			if kept, n := filterSuppressedVulns(enrichedVulns, set); n > 0 {
				enrichedVulns = kept
				fmt.Fprintf(progressStderr, "  %d SCA finding(s) suppressed by ignore rules\n", n)
			}
		}
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
			rep.Complete("autofix dry run complete")
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
					rep.Complete("autofix applied")
					printAutofixReport(selected, selectedCounts, len(resolvedFindings), nil)
					if vexPath != "" {
						fmt.Fprintf(os.Stdout, "  VEX: %s\n", vexPath)
					}
					fmt.Fprintln(os.Stderr, "Re-scanning to confirm SCA autofix results...")

					// Same run, four deliberate differences. Copying opts rather
					// than re-listing every field means a new option cannot be
					// silently dropped from the confirmation pass.
					confirmOpts := opts
					// SCA-only: a dependency fix changes only SCA, so re-running
					// SAST/secrets/containers/IaC just doubles the cost. NoSCA is
					// left as-is so SCA re-runs and confirms the fixes.
					confirmOpts.NoSASTRules = true
					confirmOpts.NoSecrets = true
					confirmOpts.NoContainers = true
					confirmOpts.NoIAC = true
					// Autofix already ran; this pass verifies it.
					confirmOpts.DryRun = false
					confirmOpts.SCAAutofix = false
					confirmOpts.SCAAutofixOpts = autofix.Options{}
					confirmOpts.AutofixResolved = resolvedFindings

					return runLocalScan(
						ctx,
						confirmOpts,
						outCfg,
						// Its own activity, not the caller's. The outer run has not
						// finished yet, and Complete/Fail are finish-once, so sharing a
						// reporter would let this nested confirmation scan close the
						// outer progress row early. This matches what the nested call
						// did before the extraction, when it built its own
						// display.Progress internally.
						pipeline.NewTerminalReporter("Scan", 7, silent, noProgress),
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
	var mem *memory.Memory
	if !disableMemory {
		mem, _ = memory.Load(vulnetixDir)
	}
	if mem == nil {
		// Also the --disable-memory case: downstream writers stay non-nil and
		// simply operate on a scratch value that is never persisted.
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
		rep.Stage(fmt.Sprintf("Loading %s rules", strings.ToLower(analysisLabel)))
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
					modules = sast.FilterModulesToKinds(modules, lockedKinds)
				} else {
					modules = sast.FilterModulesByKind(modules, noSASTRules, noSecrets, noContainers, noIAC)
				}
			}
			modules = sast.FilterModulesByID(modules, ruleID)
			eng := sast.NewEngine(modules, rootPath)
			var eerr error
			rep.Stage(fmt.Sprintf("Evaluating %d %s rule(s)", len(modules), strings.ToLower(analysisLabel)))
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
				RespectGitignore:     respectGitignore,
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
		var nosecHits []sast.NosecHit
		if sastReport != nil {
			// nosec source pass + org/local suppression filter — run before any
			// report output (SARIF, memory records, summary) consumes findings.
			// Both cover every rego-engine kind (sast/secrets/iac/container).
			if kept, hits := sast.ApplyNosec(sastReport.Findings, rootPath); len(hits) > 0 {
				sastReport.Findings = kept
				nosecHits = hits
				sastReport.Degradations = append(sastReport.Degradations,
					fmt.Sprintf("%d finding(s) suppressed by nosec comments", len(hits)))
			}
			if suppSet := buildScanSuppressionSet(mem, gitCtx); suppSet != nil && !suppSet.Empty() {
				if kept, n := filterSuppressedFindings(sastReport.Findings, suppSet); n > 0 {
					sastReport.Findings = kept
					sastReport.Degradations = append(sastReport.Degradations,
						fmt.Sprintf("%d finding(s) suppressed by ignore rules", n))
				}
			}

			// Test-suite attribution: mark findings that live in the project's
			// test code, corroborated by test-runner config files and declared
			// test-framework dependencies found in the repo. The resulting
			// metadata rides the SARIF (result properties) + typed wire findings,
			// and the detected config files ride the SAST env. Run before SARIF
			// build so both on-disk and uploaded artefacts carry it.
			var testSuppressionMints []vdb.CliSuppressionMint
			testActive := testsuite.Scan(rootPath)
			testMarked := testsuite.Annotate(sastReport.Findings, testActive)
			testConfigMeta := testConfigsToWire(testActive.Configs)
			if testMarked > 0 {
				sastReport.Degradations = append(sastReport.Degradations,
					fmt.Sprintf("%d finding(s) attributed to test suites", testMarked))
			}
			// Optionally suppress test-code SAST findings when the user opts in.
			if suppressTestCode && testMarked > 0 {
				if kept, mints := suppressTestFindings(sastReport.Findings, gitCtx); len(mints) > 0 {
					sastReport.Findings = kept
					testSuppressionMints = mints
					sastReport.Degradations = append(sastReport.Degradations,
						fmt.Sprintf("%d test-code finding(s) suppressed (--suppress-test-code)", len(mints)))
				}
			}

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

				// Verify-then-resolve via on-disk inspection. Only the kinds whose
				// rules actually ran in this invocation may be reconciled: a
				// `vulnetix secrets` run evaluates no Dockerfile rules, so every
				// container finding would look "absent" and be resolved.
				verifier := func(loc memory.Location) (bool, string) {
					return scan.VerifyLocationGone(rootPath, loc, 5)
				}
				ranTools := make([]string, 0, 4)
				if !noSASTRules {
					ranTools = append(ranTools, memory.ToolSAST)
				}
				if !noSecrets {
					ranTools = append(ranTools, memory.ToolSecrets)
				}
				if !noIAC {
					ranTools = append(ranTools, memory.ToolIaC)
				}
				if !noContainers {
					ranTools = append(ranTools, memory.ToolContainer)
				}
				for _, tool := range ranTools {
					changes := mem.ReconcileTool(memory.ReconcileContext{
						Tool:       tool,
						Mode:       memory.ResolveOnVerify,
						CurrentIDs: currentByTool[tool],
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
				sarifLog.AddExecutionNotifications(sastReport.Degradations)
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
				rep.Stage("Persisting container BOM")
				// The persisted findings are not consumed on the container path:
				// the VEX/autofix passes that read them have already run above.
				apiServed, apiInsights, apiSnapshotUuid, apiSnapshotURL, _ := postCliSCABOM(allPackages, manifestGroups, licenseByKey, gitCtx, sysInfo, rootPath, "vulnetix-containers", io.Discard)
				if apiServed {
					scaInsights = apiInsights
					scaSnapshotUuid = apiSnapshotUuid
					scaSnapshotURL = apiSnapshotURL
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
			// Reconcile code-anchored suppressions: fold this scan's nosec
			// directives into memory and drift-track existing snippet-anchored
			// rules (relocating file/line, auto-deactivating gone anchors). Runs
			// regardless of auth so nosec persists offline; the mint list is only
			// sent when authenticated.
			var suppressionMints []vdb.CliSuppressionMint
			if !disableMemory {
				suppressionMints = reconcileScanSuppressions(mem, gitCtx, nosecHits, rootPath, time.Now().Unix())
			}
			// Test-code suppressions (--suppress-test-code) ride the same mint list.
			suppressionMints = append(suppressionMints, testSuppressionMints...)
			if !isUnauthenticatedScan() {
				// Which SARIF-family scanners actually ran — an enabled one that
				// found nothing still submits so the backend records coverage.
				enabledKinds := map[string]bool{
					"sast":    !noSASTRules,
					"secrets": !noSecrets,
					"iac":     !noIAC,
					"oci":     !noContainers,
				}
				var suppResults []vdb.CliSuppressionResult
				sarifSnapshots, sarifSnapshotUuids, suppResults = postScanSARIF(sastReport, enabledKinds, gitCtx, rootPath, snippetContext, scaSnapshotUuid, suppressionMints, testConfigMeta, progressStderr)
				applyMintedSuppressionUUIDs(mem, suppResults)
				// Hand the container scan's snapshot to the ELF pass, which runs
				// after this function returns (cmd/specialized_scans.go). Without
				// it the binary inventory opens a second snapshot and one
				// `vulnetix containers` shows up twice in the console.
				if u := sarifSnapshotUuids["containers"]; u != "" {
					lastContainerSnapshotUuid = u
				} else {
					lastContainerSnapshotUuid = scaSnapshotUuid
				}
			}
		}
	}
	if sastReport != nil {
		rep.Update(5, fmt.Sprintf("%s analysis found %d issue(s)", analysisLabel, len(sastReport.Findings)))
	} else {
		rep.Update(5, fmt.Sprintf("%s analysis skipped or produced no findings", analysisLabel))
	}

	rep.Stage("Persisting scan memory")

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

	// ── License analysis (unless --no-licenses) ────────────────────────────
	// The `license` command owns this: runLicensePipeline is the single
	// implementation of detect → policy → suppression → memory reconcile, so
	// `scan --evaluate-licenses --allow MIT` and `license --allow MIT` agree.
	var licenseResult *license.AnalysisResult
	var licenseVEX []cdx.Vulnerability
	if !noLicenses {
		licenseMem := mem
		if disableMemory {
			licenseMem = nil
		}
		run, lerr := runLicensePipeline(LicenseRunOptions{
			RootPath:         rootPath,
			Mode:             licensePolicy.Mode,
			AllowCSV:         licensePolicy.AllowCSV,
			AllowFile:        licensePolicy.AllowFile,
			Packages:         allPackages,
			ManifestGroups:   manifestGroups,
			LicensedPackages: licensedPackages, // reuse the pre-SCA detection
			Memory:           licenseMem,
			GitCtx:           gitCtx,
			Stderr:           progressStderr,
		})
		if lerr != nil {
			return lerr
		}
		licenseResult = run.Result
		licenseVEX = run.VEXVulnerabilities

		bom.Vulnerabilities = append(bom.Vulnerabilities, run.FindingVulnerabilities...)
		cdx.PopulateLicenses(bom, run.LicenseSpdxIDByPackage(), license.CanonicalSPDXID)
		stateChanges = append(stateChanges, run.StateChanges...)
	}

	// ── VEX fan-out ───────────────────────────────────────────────────────
	// Each scanner attests its state changes in the channel it owns. SCA and
	// license write CycloneDX VEX into the BOM; the static-analysis family
	// writes OpenVEX. Mixing them — as this once did, stamping SAST
	// fingerprints into the BOM under source "vulnetix-sca" — produces an SBOM
	// full of vulnerabilities that are not vulnerabilities and no OpenVEX at all.
	changesByTool := partitionChangesByTool(stateChanges)
	var cdxVEX []cdx.Vulnerability
	if !suppressBOM {
		cdxVEX = cdxVEXForChanges(changesByTool[memory.ToolSCA], "vulnetix-sca")
		// License VEX is read from memory rather than from this run's changes:
		// the entries must reappear on every run, not only on the one that
		// resolved them (see licenseVEXFromMemory, called inside the pipeline).
		cdxVEX = append(cdxVEX, licenseVEX...)
	}

	// Populate dependency tree from manifest group edges.
	compRefs := cdx.ExportCompRefs(bom)
	bom.Dependencies = cdx.BuildDependencies(manifestGroups, compRefs)

	// Skip writing an empty SBOM: a SAST-only scan resolves 0 packages, so the
	// BOM would have no components or vulnerabilities — the SARIF is the
	// relevant artefact in that case. Don't claim a BOM artefact we didn't write.
	bomWritten := false
	if !suppressBOM && (len(bom.Components) > 0 || len(bom.Vulnerabilities) > 0 || len(cdxVEX) > 0) {
		if existingBOM, err := parseCDXForScan(sbomPath); err == nil && existingBOM != nil {
			bom = cdx.MergeBOMs(existingBOM, bom)
		}
		// After the merge, so a resolution annotates the vulnerability entry the
		// previous run left on disk instead of appending a twin under the same id.
		cdx.ApplyVEXAnalysis(bom, cdxVEX)
		if err := writeBOMToFile(bom, sbomPath); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: could not write BOM: %v\n", err)
		} else {
			bomWritten = true
		}
	}
	if !bomWritten {
		rec.SBOMPath = "" // omitempty → not serialised into memory.yaml
	}

	// Static-analysis findings (sast / secrets / iac / container) are attested as
	// OpenVEX regardless of whether this scan also produced a BOM — their
	// identifiers are rule fingerprints, which have no meaning in a CycloneDX
	// `vulnerabilities` array. The paths are surfaced with the other artefacts
	// at the end of the run, not here, where the findings tables would bury them.
	vexPaths := writeOpenVEXForPartition(rootPath, changesByTool)

	// --disable-memory means exactly that: nothing is read from or written to
	// memory.yaml. The scan record is not persisted either — a memory file that
	// exists only to hold scan history is still a memory file.
	if !disableMemory {
		recordAutofixMemoryEvents(mem, autofixResolved)
		mem.RecordScan(rec)
		if err := memory.Save(vulnetixDir, mem); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: could not update memory.yaml: %v\n", err)
		}
		rep.Update(6, "Wrote local scan state")
	} else {
		rep.Update(6, "Skipped local scan state (--disable-memory)")
	}

	graphToolName := "vulnetix-scan-graph"
	switch {
	case containerOnly:
		graphToolName = "vulnetix-containers-graph"
	case iacOnly:
		graphToolName = "vulnetix-iac-graph"
	case secretsOnly:
		graphToolName = "vulnetix-secrets-graph"
	case noSCA && !disableAllSAST:
		graphToolName = "vulnetix-static-graph"
	}
	postScannerGraphInsights(rootPath, graphToolName, gitCtx, progressStderr)

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
	//
	// GRADED for reporting, but the BLOCKING behaviour is unchanged. Each
	// end-of-life date is mapped to a synthetic severity by how close it is
	// (retired / within 30 days / this quarter / next quarter) using the org's own
	// mapping, so a runtime that died two years ago and one that dies next quarter
	// stop looking like the same problem. A bucket the org set to "skip" produces
	// nothing at all.
	//
	// Only components AT OR ABOVE the block floor actually fail the build, and the
	// floor defaults to `critical`, which is the `retired` bucket's default
	// severity. So out of the box exactly what failed a build yesterday fails it
	// today, and everything else is reported rather than enforced. Grading a
	// next-quarter EOL into a red build would turn an upgrade of the CLI into a
	// fleet-wide CI outage, and a gate that does that gets switched off — which
	// protects nobody.
	//
	// An org opts into stricter blocking with --block-eol-severity (high, medium,
	// low). Doing it through the org's quality-gate policy needs a column that does
	// not exist yet; that is a follow-up, not a reason to ship a breaking default.
	//
	// This is what the four eol*Severity columns were always for. Nothing read them
	// until organisations started being seeded a policy row — before that,
	// cli.quality-gate-get answered {"config": null} for every org alive and the
	// CLI never got as far as looking.
	if blockEOL {
		eolClient := newSearchClient()
		pins := scan.DetectRuntimeVersionPins(rootPath)
		now := time.Now()

		type eolItem struct {
			label    string
			severity string
			horizon  scan.EOLHorizon
		}
		var graded []eolItem

		grade := func(eolFrom, label string) {
			horizon := scan.EOLHorizonOf(eolFrom, now)
			severity, ok := orgEOLBuckets.SeverityFor(horizon)
			if !ok {
				return
			}
			graded = append(graded, eolItem{label: label, severity: severity, horizon: horizon})
		}

		for _, pin := range pins {
			resp, err := eolClient.EOLRelease(pin.Product, pin.Release)
			if err != nil {
				continue // silently skip: unknown product / network error
			}
			eolFrom := ""
			if resp.Release.EolFrom != nil {
				eolFrom = *resp.Release.EolFrom
			}
			// An EOL feed that says "this is EOL" but gives no date still means EOL.
			if eolFrom == "" && resp.Release.IsEol {
				eolFrom = now.Format("2006-01-02")
			}
			grade(eolFrom, fmt.Sprintf("%s %s (%s)", pin.Product, pin.RawVersion, pin.SourceFile))
		}

		// Package-level EOL — from /v2/cli.sca PackageInsights (the server maps
		// each package to its EolProduct/EolRelease and matches the installed
		// version's release line). Packages with no EOL row are skipped.
		seenPkgEol := map[string]bool{}
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
			if !ok {
				continue
			}
			eolFrom := ins.EOLFrom
			if eolFrom == "" && ins.IsEOL {
				eolFrom = now.Format("2006-01-02")
			}
			grade(eolFrom, fmt.Sprintf("%s@%s (%s)", p.Name, p.Version, p.Ecosystem))
		}

		// One breach per severity, so the report reads as a priority list rather
		// than one undifferentiated pile. Only severities at or above the floor
		// breach; the rest are reported and do not fail the build.
		var approaching []eolItem
		for _, severity := range []string{"critical", "high", "medium", "low"} {
			var labels []string
			for _, item := range graded {
				if item.severity != severity {
					continue
				}
				if !scan.SeverityMeetsThreshold(severity, eolBlockSeverity) {
					approaching = append(approaching, item)

					continue
				}
				labels = append(labels, item.label)
			}
			if len(labels) == 0 {
				continue
			}
			breaches = append(breaches, GateBreach{
				Gate:  "eol",
				Count: len(labels),
				Message: fmt.Sprintf("--block-eol (%s): %s end-of-life: %s",
					severity, pluralise("component", len(labels)), strings.Join(labels, ", ")),
			})
		}

		// Approaching end-of-life. Not a breach — said plainly so it can be planned
		// for, rather than discovered on the day it starts failing the build.
		if len(approaching) > 0 && !resultsOnly {
			fmt.Fprintf(os.Stderr, "\nApproaching end-of-life (not blocking; raise with --block-eol-severity):\n")
			for _, item := range approaching {
				fmt.Fprintf(os.Stderr, "  %-14s %s (%s)\n", item.horizon, item.label, item.severity)
			}
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
	rep.Update(7, "Evaluated quality gates")

	// ── Jail (--jail) ─────────────────────────────────────────────────────
	//
	// Runs AFTER finalization so the snapshots this scan just created exist
	// server-side, and their uuids are handed to the gate so read-replica lag
	// cannot make the scan-then-gate sequence read its own upload as missing.
	//
	// Staleness stays meaningful in this mode: this invocation refreshed only
	// the categories it actually ran. The useful verdict from `sca --jail` is
	// "SCA current and clean, SAST forty days old — indeterminate", which is
	// exactly what the per-category coverage resolution produces.
	jailIndeterminate := false
	if opts.Jail {
		jailBreaches, indeterminate, jerr := runJailPassForScan(ctx, rootPath, finalizedSnapshotList(scaSnapshotUuid, sarifSnapshotUuids))
		if jerr != nil {
			fmt.Fprintf(os.Stderr, "  warning: jail evaluation failed: %v\n", jerr)
		} else {
			breaches = append(breaches, jailBreaches...)
			jailIndeterminate = indeterminate
		}
	}

	rep.Complete("scan complete")

	// ── Output ────────────────────────────────────────────────────────────

	// Write any requested file outputs.
	//
	// A file the user asked for and did not get is a failure, not a warning: a
	// pipeline whose next step reads the SBOM would otherwise carry on against
	// a missing or stale file and exit 0. The findings and the quality gate are
	// still printed first — the error is folded into the return value below, so
	// a policy breach (which is more actionable) still wins the exit code.
	var outputWriteErr error
	defer func() {
		if retErr == nil && outputWriteErr != nil {
			retErr = outputWriteErr
		}
	}()
	if outCfg.cdxFile != "" {
		outBOM := cdx.BuildFromLocalScan(localResults, "1.7", scanCtx, seedBOM)
		// Carry the dependency tree into the file output too, so `-o file.cdx.json`
		// is as complete as the canonical .vulnetix/sbom.cdx.json.
		outBOM.Dependencies = cdx.BuildDependencies(manifestGroups, cdx.ExportCompRefs(outBOM))
		if err := writeBOMToFile(outBOM, outCfg.cdxFile); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ could not write CDX to %s: %v\n", outCfg.cdxFile, err)
			outputWriteErr = fmt.Errorf("could not write CDX to %s: %w", outCfg.cdxFile, err)
		}
	}
	if outCfg.sarifFile != "" && sastReport != nil {
		sarifLog := sast.BuildSARIF(sastReport.Findings, sastReport.Rules, version)
		sarifLog.AddExecutionNotifications(sastReport.Degradations)
		if err := sast.WriteSARIF(sarifLog, outCfg.sarifFile); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ could not write SARIF to %s: %v\n", outCfg.sarifFile, err)
			if outputWriteErr == nil {
				outputWriteErr = fmt.Errorf("could not write SARIF to %s: %w", outCfg.sarifFile, err)
			}
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
		if err := jailIndeterminateError(breaches, jailIndeterminate); err != nil {
			return err
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
			sarifLog.AddExecutionNotifications(sastReport.Degradations)
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
		if err := jailIndeterminateError(breaches, jailIndeterminate); err != nil {
			return err
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
	// --results-only promises silence on a clean tree. Every renderer below
	// prints something unconditionally — the divider and the
	// "0 packages | 0 vulnerabilities" footer, then the artefact links — so a
	// clean scan still produced output that a pipeline grepping for "no news"
	// had to filter. Nothing found, nothing printed.
	if resultsOnly && scanFoundNothing(enrichedVulns, sastReport, licenseResult, breaches) {
		return nil
	}

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
	printScanArtifacts(displaySBOM, sarifPath, vulnetixDir, rulesPath, scaSnapshotURL, vexPaths, sarifSnapshots)
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
	// Exit 3 only when nothing breached. A definite violation is more actionable
	// than an unknown, so a breach anywhere wins the exit code.
	if err := jailIndeterminateError(breaches, jailIndeterminate); err != nil {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "  ? jail could not be evaluated: some rules have no current scan coverage")
		return err
	}
	if autofixReportErr != nil {
		return autofixReportErr
	}
	return nil
}

// ---------------------------------------------------------------------------
// Dry-run
// ---------------------------------------------------------------------------

// scanFeatureScope is the set of feature toggles the engine resolved for this
// invocation. It travels to the dry run so the report describes what *this*
// command would do rather than what the generic `scan` would.
type scanFeatureScope struct {
	NoSAST       bool
	NoSCA        bool
	NoLicenses   bool
	NoSecrets    bool
	NoContainers bool
	NoIAC        bool
}

// packageScopeActive reports whether any pass consumes parsed dependency
// manifests. `secrets`/`sast` do not, so their dry run skips manifest parsing.
func (s scanFeatureScope) packageScopeActive() bool {
	return !s.NoSCA || !s.NoContainers || !s.NoIAC || !s.NoLicenses
}

// sastScopeActive reports whether any rego-engine pass runs.
func (s scanFeatureScope) sastScopeActive() bool {
	return !s.NoSAST || !s.NoSecrets || !s.NoContainers || !s.NoIAC
}

// enabledLabels names the passes this scope runs, for the dry-run header.
func (s scanFeatureScope) enabledLabels() []string {
	var out []string
	for _, p := range []struct {
		off  bool
		name string
	}{
		{s.NoSCA, "sca"},
		{s.NoSAST, "sast"},
		{s.NoSecrets, "secrets"},
		{s.NoContainers, "containers"},
		{s.NoIAC, "iac"},
		{s.NoLicenses, "licenses"},
	} {
		if !p.off {
			out = append(out, p.name)
		}
	}
	return out
}

// dryScanOptions is the input to runDryScan.
type dryScanOptions struct {
	RootPath          string
	Depth             int
	Excludes          []string
	SeverityThreshold string
	Scope             scanFeatureScope
	// RespectGitignoreManifest mirrors the live walk so the file list matches.
	RespectGitignoreManifest bool
	// Rule inputs describe the SAST-family side of the plan. External rule packs
	// are NOT fetched during a dry run (that is a network call); they are reported
	// as pending instead.
	RuleRefs            []sast.RuleRef
	RuleRegistry        string
	DisableDefaultRules bool
	LockedKinds         []string
}

// runDryScan performs the local detection and parsing pipeline without making any
// network (API) calls, scoped to the passes the invoking command enables. After
// detection it checks for existing scan memory (.vulnetix/sbom.cdx.json) and
// renders it exactly as `vulnetix report` would, but still without API calls.
func runDryScan(opts dryScanOptions) error {
	scanPath := opts.RootPath
	depth := opts.Depth
	excludes := opts.Excludes
	severityThreshold := opts.SeverityThreshold
	scope := opts.Scope

	t := display.NewTerminal()

	// ── Header ────────────────────────────────────────────────────────────
	fmt.Fprintln(os.Stderr, display.Bold(t, "[DRY RUN]"),
		display.Muted(t, "— no API calls will be made"))
	if labels := scope.enabledLabels(); len(labels) > 0 {
		fmt.Fprintf(os.Stderr, "Passes: %s\n", strings.Join(labels, ", "))
	}
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

	// ── 2. Report the rule plan for the rego-engine passes ────────────────
	if scope.sastScopeActive() {
		reportDryRunRulePlan(t, opts)
	}

	// ── 3. Discover files ─────────────────────────────────────────────────
	files, err := scan.WalkForScanFiles(scan.WalkOptions{
		RootPath:         scanPath,
		MaxDepth:         depth,
		Excludes:         excludes,
		RespectGitignore: opts.RespectGitignoreManifest,
	})
	if err != nil {
		return fmt.Errorf("failed to scan directory: %w", err)
	}
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "No scannable files detected.")
		return nil
	}
	// A SARIF-family-only command (sast / secrets) parses no dependency
	// manifests: its plan is the rule set plus the tree it will walk, which the
	// rule plan above already reported.
	if !scope.packageScopeActive() {
		fmt.Fprintf(os.Stderr, "\n%s %d file(s) discovered; dependency parsing skipped for this scope.\n",
			display.CheckMark(t), len(files))
		return dryRunRenderMemory(t, scanPath)
	}

	// ── 4. Display detected files ─────────────────────────────────────────
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
			spdxComponents, spdxErr := parseSPDXForScan(f.Path)
			if showDetectedFiles {
				fmt.Fprintf(os.Stderr, "  %-40s spdx        v%-8s (%d pkg)\n", f.RelPath, f.SBOMVersion, len(spdxComponents))
			}
			if spdxErr == nil && len(spdxComponents) > 0 {
				f.Supported = true
				supportedFiles = append(supportedFiles, f)
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

	// The live pipeline filters the file list by the active features; mirror that
	// so a scoped dry run does not promise passes over files it would skip.
	supportedFiles = filterFilesByFeature(supportedFiles, scope.NoSCA, scope.NoContainers, scope.NoIAC)

	if len(supportedFiles) == 0 {
		fmt.Fprintln(os.Stderr, "\nNo supported manifest files found for scanning.")
		return dryRunRenderMemory(t, scanPath)
	}

	// ── 5. Parse manifests (local only, no network) ───────────────────────
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Parsing manifests (local):")
	totalPkgs := 0
	for _, f := range supportedFiles {
		// SBOM input files (CycloneDX or SPDX): extract components as packages.
		if f.FileType == scan.FileTypeCycloneDX || f.FileType == scan.FileTypeSPDX {
			components, err := sbomComponentsForScan(f)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  %-40s parse error: %v\n", f.RelPath, err)
				continue
			}
			pkgs := buildPackagesFromCDX(components, f.RelPath)
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

	// ── 7. Check memory ───────────────────────────────────────────────────
	return dryRunRenderMemory(t, scanPath)
}

// reportDryRunRulePlan describes the rego-engine side of a dry run: which rule
// kinds would evaluate, and which external packs would be fetched. The packs are
// only named — fetching one is a network call, which a dry run must not make.
func reportDryRunRulePlan(t *display.Terminal, opts dryScanOptions) {
	kinds := opts.LockedKinds
	if len(kinds) == 0 {
		kinds = enabledRuleKinds(opts.Scope)
	}
	if len(kinds) > 0 {
		fmt.Fprintf(os.Stderr, "Rule kinds: %s\n", strings.Join(kinds, ", "))
	}
	if opts.DisableDefaultRules {
		fmt.Fprintf(os.Stderr, "%s built-in rules disabled (--disable-default-rules)\n",
			display.Muted(t, "ℹ"))
	}
	for _, ref := range opts.RuleRefs {
		registry := opts.RuleRegistry
		if registry == "" {
			registry = sast.DefaultRegistry
		}
		fmt.Fprintf(os.Stderr, "%s external rule pack %s/%s would be fetched from %s\n",
			display.Muted(t, "ℹ"), ref.Org, ref.Repo, registry)
	}
	fmt.Fprintln(os.Stderr)
}

// enabledRuleKinds maps the feature scope onto the rego rule kinds it evaluates.
func enabledRuleKinds(scope scanFeatureScope) []string {
	var kinds []string
	for _, k := range []struct {
		off  bool
		name string
	}{
		{scope.NoSAST, "sast"},
		{scope.NoSecrets, "secrets"},
		{scope.NoContainers, "oci"},
		{scope.NoIAC, "iac"},
	} {
		if !k.off {
			kinds = append(kinds, k.name)
		}
	}
	return kinds
}

// dryRunRenderMemory renders previously-stored results with zero API calls. It is
// the same replay `vulnetix report` performs, which is why both go through
// LoadFromMemory.
func dryRunRenderMemory(t *display.Terminal, scanPath string) error {
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
// scanFoundNothing reports whether the run produced nothing a reader would act
// on: no vulnerabilities, no SAST/secrets/IaC/container findings, no license
// findings, and no policy breach. It backs --results-only.
func scanFoundNothing(enrichedVulns []scan.EnrichedVuln, sastReport *sast.SASTReport, licenseResult *license.AnalysisResult, breaches []GateBreach) bool {
	if len(enrichedVulns) > 0 || len(breaches) > 0 {
		return false
	}
	if sastReport != nil && len(sastReport.Findings) > 0 {
		return false
	}
	if licenseResult != nil && len(licenseResult.Findings) > 0 {
		return false
	}
	return true
}

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

// printScanArtifacts prints the artefact links (BOM / Memory / SARIF / Rules and
// ingestion snapshot URLs) at the very bottom of the scan output, after all
// analysis tables. Each line is gated on a non-empty value. scaSnapshotURL is
// the /v2/cli.sca snapshot; snapshots carries one link per SARIF kind
// (SAST/Secrets/IaC/Containers) submitted this scan.
func printScanArtifacts(sbomPath, sarifPath, vulnetixDir, rulesPath, scaSnapshotURL string, vexPaths []string, snapshots []snapshotLink) {
	t := display.NewTerminal()
	if sbomPath != "" {
		fmt.Fprintf(os.Stdout, "  %s BOM:      %s\n", display.CheckMark(t), sbomPath)
	}
	if !disableMemory {
		fmt.Fprintf(os.Stdout, "  %s Memory:   %s\n", display.CheckMark(t), filepath.Join(vulnetixDir, memory.FileName))
	}
	if sarifPath != "" {
		fmt.Fprintf(os.Stdout, "  %s SARIF:    %s\n", display.CheckMark(t), sarifPath)
	}
	for _, vexPath := range vexPaths {
		fmt.Fprintf(os.Stdout, "  %s VEX:      %s\n", display.CheckMark(t), vexPath)
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
	fmt.Fprintln(os.Stderr, "    https://www.vulnetix.com/resolve/register, then run 'vulnetix auth login'.")
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
		if p.Name != "" {
			seen[p.Name+"::"+p.Ecosystem] = true
		}
	}
	return len(seen)
}

// countUniqueMap returns a map of "name::ecosystem" → package (for dedup counting in display).
// Applies the same empty-name filter as countUniquePackages so the counts agree.
// Short names are counted: `db` (crystal), `qs`/`ms` (npm) and `q` are real
// packages, and dropping them made the summary disagree with both the SBOM and
// the number of packages actually sent to the VDB.
func countUniqueMap(packages []scan.ScopedPackage) map[string]scan.ScopedPackage {
	m := map[string]scan.ScopedPackage{}
	for _, p := range packages {
		if p.Name == "" {
			continue
		}
		key := p.Name + "::" + p.Ecosystem
		if _, exists := m[key]; !exists {
			m[key] = p
		}
	}
	return m
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

// sbomComponentsForScan returns the components of a detected SBOM input file,
// whichever of the two formats it is written in.
func sbomComponentsForScan(f scan.DetectedFile) ([]cdx.Component, error) {
	if f.FileType == scan.FileTypeSPDX {
		return parseSPDXForScan(f.Path)
	}
	bom, err := parseCDXForScan(f.Path)
	if err != nil {
		return nil, err
	}
	return bom.Components, nil
}

// parseSPDXForScan reads an SPDX 2.x document and returns its packages as
// CycloneDX components, so an SPDX input joins the scan through the same
// component→package path a CycloneDX input takes. A package without a purl
// carries no ecosystem and cannot be matched, so it is dropped.
func parseSPDXForScan(path string) ([]cdx.Component, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	doc, err := parseSPDXPackages(data)
	if err != nil {
		return nil, err
	}
	components := make([]cdx.Component, 0, len(doc.packages))
	for _, p := range doc.packages {
		components = append(components, cdx.Component{
			Type:    "library",
			Name:    p.Name,
			Version: p.Version,
			Purl:    p.Purl,
		})
	}
	return components, nil
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
	// Retired. It was parsed and threaded through the whole scan engine without
	// ever being read; SCA fan-out is governed by VULNETIX_SCA_CONCURRENCY
	// (default 6, see cmd/cli_sca.go). Deprecated rather than deleted so a CI
	// pipeline that passes it keeps working with a warning instead of failing
	// on "unknown flag". Delete in v4.
	cmd.Flags().Int("concurrency", 5, "Max concurrent VDB queries")
	_ = cmd.Flags().MarkDeprecated("concurrency",
		"it has never had any effect; set VULNETIX_SCA_CONCURRENCY instead")
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
	cmd.Flags().Bool("jail", false, "After uploading, assess this repository against the organisation's jail policy and gate on the result. Exits 1 when a rule breaches and 3 when a rule cannot be evaluated against current scan coverage. Run 'vulnetix jail' for the standalone gate with artefacts.")
	cmd.Flags().Bool("block-eol", false, "Exit with code 1 when a runtime or package dependency is end-of-life. Runtimes: Go, Node.js, Python, Ruby. Package-level checks activate when VDB has EOL data (404s are silently skipped).")
	cmd.Flags().String("block-eol-severity", "critical", "With --block-eol, the graded severity at which an end-of-life component fails the build (critical, high, medium, low). Components graded below it are reported, not blocked. The default blocks only what is already past its end-of-life date.")
	cmd.Flags().Bool("block-unpinned", false, "Exit with code 1 when any direct dependency uses a version range (^, ~, >=) instead of an exact pin.")
	cmd.Flags().String("exploits", "", "Exit with code 1 when exploit maturity reaches the threshold: poc (any public exploit), active (CISA/EU KEV / actively exploited), weaponized (in-the-wild only).")
	cmd.Flags().Bool("results-only", false, "Only output when findings exist; completely silent when the scan is clean.")
	cmd.Flags().Bool("no-ci-package-analysis", false, "Skip dependency extraction from CI/CD pipeline files such as GitHub Actions, GitLab CI, CircleCI, Buildkite, Azure Pipelines and Jenkinsfiles.")
	cmd.Flags().Bool("no-shell-package-analysis", false, "Skip dependency extraction from shell scripts that install packages without a manifest.")
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
	cmd.Flags().String("reachability", "both",
		"Tree-sitter reachability mode for the CVEs this scan produces: \"direct\" (scan only each vulnerable package's installed directory), \"transitive\" (sweep the rest of the project for callers), \"both\" (default), or \"off\" (skip the analysis and the server-side query fetch). Use \"off\" or \"direct\" on large monorepos where the whole-tree sweep is too slow.")
	_ = cmd.RegisterFlagCompletionFunc("reachability",
		cobra.FixedCompletions([]string{"direct", "transitive", "both", "off"}, cobra.ShellCompDirectiveNoFileComp))
	// Secrets-only flags. They are registered on every scan-style subcommand
	// so that `scan --evaluate-secrets --ignore-git` works just as well as
	// `secrets --ignore-git`, but the flags are documented under the
	// secrets subcommand and only meaningfully affect the secrets stage.
	cmd.Flags().StringArray("ignore", nil,
		"Glob pattern (relative to scan root) to skip during the secrets stage; repeatable")
	cmd.Flags().Bool("ignore-git", false,
		"Skip the git-history secrets pass. The .git directory itself is never scanned as source; this flag additionally suppresses reading credentials out of past commits")
	cmd.Flags().Bool("ignore-binaries", false,
		"Skip binary files during the secrets stage. Default is to extract printable strings and EXIF metadata from binaries")
	cmd.Flags().Bool("git-history", true,
		"When the secrets stage runs, walk git history (newest first) and scan the file contents of every changed path")
	cmd.Flags().Int("git-history-max-commits", 500,
		"Cap the number of commits walked during the git-history secrets stage (0 = no cap)")
	cmd.Flags().Int("git-history-max-files", 5000,
		"Cap the number of file versions extracted from git history (0 = no cap)")
	cmd.Flags().Bool("include-ignored", false,
		"Include files matched by .gitignore. By default the SAST, secrets, containers and IaC passes skip gitignored paths; sca and malscan always scan them (dependency install dirs are commonly gitignored).")
	// License policy. The `license` subcommand owns the analysis; these are the
	// same knobs, registered here so a scan that evaluates licenses can carry the
	// project's policy instead of silently falling back to a permissive default.
	cmd.Flags().String("allow", "",
		"Comma-separated SPDX licenses allowed by policy during license evaluation")
	cmd.Flags().String("allow-file", "",
		"YAML allow-list file for license evaluation (overrides --allow)")
	cmd.Flags().String("license-mode", "inclusive",
		"License conflict detection mode: inclusive (whole project) or individual (per manifest)")
	_ = cmd.RegisterFlagCompletionFunc("license-mode", cobra.FixedCompletions(
		[]string{"inclusive", "individual"}, cobra.ShellCompDirectiveNoFileComp))
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

// includeIgnoredForScan reports whether the user asked to include .gitignored
// paths, honouring both the generic --include-ignored flag and the per-mode
// alias (e.g. --sast-include-ignored) registered on specialized subcommands.
func includeIgnoredForScan(cmd *cobra.Command) bool {
	for _, name := range []string{"include-ignored", cmd.Name() + "-include-ignored"} {
		if cmd.Flags().Lookup(name) == nil {
			continue
		}
		if v, _ := cmd.Flags().GetBool(name); v {
			return true
		}
	}
	return false
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
	cmd.Flags().Bool("suppress-test-code", false,
		"Suppress SAST findings located in the project's test suite (test files corroborated by test-runner config/dependencies)")
	// Registered here, not on `scan` alone: it shapes the SARIF every
	// rego-engine command emits, so sast/secrets/iac/containers must be able to
	// set it for their own output.
	cmd.Flags().Int("snippet-context", -1,
		"Surrounding non-empty source lines to capture around each SARIF finding (-1 = dynamic: 3 if span <10 lines else 5; 0 disables)")
}

// suppressTestCode is set from the --suppress-test-code flag in
// runScanWithFeatures and read by runLocalScan.
var suppressTestCode bool

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
		isContainer := lang == "docker" || lang == "kubernetes" || lang == "helm"
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

func filterCommandPackageFiles(files []scan.DetectedFile, noCI, noShell bool) []scan.DetectedFile {
	if !noCI && !noShell {
		return files
	}
	filtered := make([]scan.DetectedFile, 0, len(files))
	for _, f := range files {
		if f.ManifestInfo == nil {
			filtered = append(filtered, f)
			continue
		}
		if noCI && scan.IsCIPipelineFile(f.ManifestInfo) {
			continue
		}
		if noShell && f.ManifestInfo.Language == "shell" {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered
}

// specializedRuleKinds returns the locked Rego kind-set for a specialized scan
// subcommand, or nil for the generic "scan" command (and "sca", which runs no
// Rego). When non-nil the kinds are authoritative: only rules of these kinds
// run, embedded and externally imported alike (see sast.FilterModulesToKinds), so a
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

func init() {
	rootCmd.AddCommand(scanCmd)

	addScanFlags(scanCmd)
	addSASTFlags(scanCmd)

	// Feature control flags (scan command only — specialized commands hard-code these)
	scanCmd.Flags().Bool("evaluate-sast", false, "Enable SAST analysis")
	scanCmd.Flags().Bool("no-sast", false, "Skip SAST analysis")
	scanCmd.Flags().Bool("no-aibom", false, "Skip AI Bill of Materials (AIBOM) detection + submission during scan")
	scanCmd.Flags().Bool("no-cbom", false, "Skip Cryptography Bill of Materials (CBOM) detection + submission during scan")
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

	// Report replay, kept as deprecated aliases for `vulnetix report` so existing
	// pipelines keep working. `report` is the owner (cmd/report.go).
	scanCmd.Flags().Bool("from-memory", false, "Reconstruct scan pretty output from .vulnetix/sbom.cdx.json without API calls")
	scanCmd.Flags().Bool("fresh-exploits", false, "With --from-memory: fetch latest exploit intel from API")
	scanCmd.Flags().Bool("fresh-advisories", false, "With --from-memory: fetch latest remediation plans from API")
	scanCmd.Flags().Bool("fresh-vulns", false, "With --from-memory: re-fetch affected version checks and latest scoring from API")
	for _, f := range []string{"from-memory", "fresh-exploits", "fresh-advisories", "fresh-vulns"} {
		_ = scanCmd.Flags().MarkDeprecated(f, "use `vulnetix report`"+map[string]string{
			"from-memory":      "",
			"fresh-exploits":   " --fresh-exploits",
			"fresh-advisories": " --fresh-advisories",
			"fresh-vulns":      " --fresh-vulns",
		}[f])
	}
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
