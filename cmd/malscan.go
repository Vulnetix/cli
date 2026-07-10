package cmd

// `vulnetix malscan` runs the malscan-engine's malicious-package detection
// routines IN-PROCESS against the project's local dependency install/cache dirs
// (node_modules, .venv/site-packages, vendor, ~/.cargo, …). Unlike --block-malware
// on the sca path — which defers to the backend's periodic pipelines — this scans
// the bytes on disk directly: the STIX IOC filesystem scan (iocscan), the
// manifest/install-script pattern + shell-obfuscation detectors (detect.Detect),
// IOC extraction (ioc), and the known-bad artifact-hash blocklist (badhash).
//
// Findings are emitted as SARIF (with code samples, evidence context and host
// env), saved to .vulnetix/malscan.sarif by default, and uploaded to
// /v2/cli.malscan. Direct usage exits non-zero when any malware is found; the
// scan/sca hooks (see scan.go) gate only when --block-malware / org blockMalware
// is in effect.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vulnetix/malscan-engine/badnet"
	mconfig "github.com/vulnetix/malscan-engine/config"
	"github.com/vulnetix/malscan-engine/detect"
	"github.com/vulnetix/malscan-engine/iocscan"

	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/ecosystems"
	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/internal/memory"
)

const (
	// malscanSampleMaxBytes caps a single stored sample (the offending file).
	malscanSampleMaxBytes = 1 << 20 // 1 MiB
	// malscanManifestMaxBytes caps a manifest read for detect.Detect.
	malscanManifestMaxBytes = 512 << 10 // 512 KiB
	// malscanMaxManifests bounds how many installed-package manifests the
	// per-package detectors inspect, so a huge node_modules can't make the scan
	// run unbounded. Truncation is surfaced (no silent cap).
	malscanMaxManifests = 4000
)

var malscanCmd = &cobra.Command{
	Use:   "malscan [path]",
	Short: "Scan local dependency install dirs for malware (malscan-engine, in-process)",
	Long: `Scan a project's locally-installed dependencies for malicious code, run
entirely on the bytes on disk with the malscan-engine — no dependency on the
backend's periodic pipelines.

Four detector families run over each ecosystem's install/cache locations:
  • iocscan  — STIX IOC filesystem scan (known-bad domains/IPs/URLs in text and
               extracted binary strings), with file + line + context evidence
  • detect   — manifest / install-script pattern + shell-obfuscation detectors
  • ioc      — indicators of compromise extracted from manifests/scripts
  • badhash  — known-bad artifact-hash blocklist over declared/candidate hashes

Scan targets are resolved per ecosystem (npm node_modules, python site-packages,
go vendor, rust/cargo, ruby, php, java, dotnet, dart, elixir). User-scoped/home
caches (~/.npm, ~/go/pkg/mod, ~/.cargo, ~/.m2, …) are scanned only with
--include-home.

Evidence is SARIF, always written to .vulnetix/malscan.sarif (override with
--output-file) and uploaded to Vulnetix when authenticated. The terminal output
format is set by -o (pretty by default). Exit status is non-zero when malware is
found.

Findings are tracked in .vulnetix/memory.yaml. A finding the engine no longer
reports is marked resolved and attested in .vulnetix/vex-malscan.openvex.json.
Pass --disable-memory to turn this off.

Threat-intel definitions: the engine ships an embedded bad-IP/host/email
blocklist aggregated from public feeds. Run "malscan --fetch-definitions" to
refresh those definitions at runtime (downloaded to a local cache dir); every
subsequent scan layers them over the embedded set, so you stay current between
engine releases without recompiling. Pass --feeds with --fetch-definitions to
use a custom feeds.json source/parser mapping for the badnet blocklist refresh.

Examples:
  vulnetix malscan                       # pretty findings; writes .vulnetix/malscan.sarif
  vulnetix malscan ./app -o json         # detections as JSON
  vulnetix malscan --include-home        # also scan ~/.npm, ~/go/pkg/mod, …
  vulnetix malscan -o sarif              # print SARIF to stdout (still saved + uploaded)
  vulnetix malscan --no-ioc-feeds        # skip the STIX network fetch (detect/badhash only)
  vulnetix malscan --fetch-definitions   # refresh local threat-intel definitions, then exit
  vulnetix malscan --fetch-definitions --feeds ./feeds.json`,
	Args: cobra.MaximumNArgs(1),
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		printBanner(cmd)
		initDisplayContext(cmd, display.ModeText)
		// Credentials are optional — community/unauthenticated callers still get
		// local findings + the saved SARIF; only the upload is skipped.
		return resolveVDBCredentials(false)
	},
	RunE: runMalscanCmd,
}

func init() {
	malscanCmd.Flags().String("path", ".", "Directory to scan (defaults to CWD; resolves to the git root)")
	malscanCmd.Flags().Bool("include-home", false, "Also scan user-scoped/home install caches (~/.npm, ~/go/pkg/mod, ~/.cargo, …)")
	malscanCmd.Flags().StringP("output", "o", "pretty", "Terminal output format: pretty, json, sarif")
	malscanCmd.Flags().String("output-file", "", "Path to write the SARIF report (default: <path>/.vulnetix/malscan.sarif)")
	malscanCmd.Flags().Bool("no-binary-analysis", false, "Do not extract/match IOCs in binary files")
	malscanCmd.Flags().Int("scan-depth", 0, "Max directory depth per target (0 = unlimited)")
	malscanCmd.Flags().Int64("max-file-size", iocscan.DefaultMaxFileSize, "Skip files larger than this many bytes")
	malscanCmd.Flags().Bool("no-ioc-feeds", false, "Skip the STIX IOC filesystem scan (no network); run only detect + badhash")
	malscanCmd.Flags().String("catalog", "", "Directory of malscan capability config overrides (sets MALSCAN_CONFIG_DIR)")
	malscanCmd.Flags().String("feeds", "", "Path to a badnet feeds.json source/parser mapping for --fetch-definitions")
	malscanCmd.Flags().Bool("no-upload", false, "Do not submit findings to Vulnetix (submitted automatically when authenticated)")
	malscanCmd.Flags().Bool("fetch-definitions", false, "Fetch ALL threat-intel feeds fresh (badnet blocklists + vulnetix STIX index + TweetFeed) and rebuild local malscan definitions (no scan); subsequent scans use them")
	rootCmd.AddCommand(malscanCmd)
}

// malscanOptions are the resolved inputs to a malscan run.
type malscanOptions struct {
	Root           string
	IncludeHome    bool
	BinaryAnalysis bool
	Depth          int
	MaxFileSize    int64
	IOCFeeds       bool   // run the iocscan STIX network pass
	ConfigDir      string // malscan capability override dir (MALSCAN_CONFIG_DIR)
	BadnetDir      string // runtime badnet definitions overlay dir (from --fetch-definitions)
	Progress       func(stage string)
}

// malscanSample is the offending-file content stored alongside an IOC.
type malscanSample struct {
	SHA256  string
	Name    string
	Content []byte
}

// malscanIOC is one indicator of compromise the run surfaced.
type malscanIOC struct {
	Type       string
	Value      string
	Ecosystem  string
	FilePath   string // relative to scan root
	RuleID     string
	Severity   string
	References []string
	Sample     *malscanSample
}

// malscanFinding is the unified internal finding the SARIF + pretty + upload
// layers all read from.
type malscanFinding struct {
	RuleID      string
	Title       string
	Description string // rule-level description (drives the SARIF rule descriptor)
	Message     string // per-finding message (carries the matched sample when there is no line)
	Severity    string // critical|high|medium|low|info
	Level       string // error|warning|note
	Ecosystem   string
	File        string // relative to scan root ("" for package-level)
	StartLine   int
	EndLine     int
	Snippet     string
	CWEs        []int
	Class       string // evidence|trigger|context
	Category    string
	Tags        []string
	Fingerprint string
	IOCType     string
	IOCValue    string
}

// malscanResult aggregates everything one scan produced.
type malscanResult struct {
	Findings       []malscanFinding
	IOCs           []malscanIOC
	Targets        []ecosystems.Target
	Host           iocscan.HostInfo
	Warnings       []string
	FilesScanned   int
	IndicatorCount int
	Malicious      bool
	MaliciousNote  string // short summary for the gate message
}

func runMalscanCmd(cmd *cobra.Command, args []string) error {
	dctx := display.FromCommand(cmd)
	progress := dctx.Progress("Malware scan", 6)
	progressComplete := false
	defer func() {
		if !progressComplete {
			progress.Fail("failed")
		}
	}()

	rootPath, _ := cmd.Flags().GetString("path")
	pathExplicit := cmd.Flags().Changed("path")
	if len(args) == 1 && args[0] != "" {
		rootPath = args[0]
		pathExplicit = true
	}
	outputFmt, _ := cmd.Flags().GetString("output")
	switch outputFmt {
	case "pretty", "table", "json", "sarif":
	default:
		return fmt.Errorf("--output must be one of: pretty, json, sarif")
	}
	outputFile, _ := cmd.Flags().GetString("output-file")
	includeHome, _ := cmd.Flags().GetBool("include-home")
	noBinary, _ := cmd.Flags().GetBool("no-binary-analysis")
	depth, _ := cmd.Flags().GetInt("scan-depth")
	maxFileSize, _ := cmd.Flags().GetInt64("max-file-size")
	noFeeds, _ := cmd.Flags().GetBool("no-ioc-feeds")
	catalog, _ := cmd.Flags().GetString("catalog")
	feedsFile, _ := cmd.Flags().GetString("feeds")
	noUpload, _ := cmd.Flags().GetBool("no-upload")
	fetchDefs, _ := cmd.Flags().GetBool("fetch-definitions")

	// --fetch-definitions: refresh the local threat-intel definitions from the
	// upstream feeds and exit. This lets a customer update malscan's bad-IP/host
	// definitions at runtime, between engine releases, without recompiling.
	defsDir := malscanDefinitionsDir()
	if fetchDefs {
		return runFetchDefinitions(defsDir, feedsFile)
	}
	if strings.TrimSpace(feedsFile) != "" {
		return fmt.Errorf("--feeds is only used with --fetch-definitions")
	}

	// Resolve the scan root: an explicit --path / positional arg is used as-is;
	// otherwise default to CWD and prefer the enclosing git root. Always absolute.
	if rootPath == "" {
		rootPath = "."
	}
	gitCtx := gitctx.Collect(rootPath)
	if !pathExplicit && gitCtx != nil && gitCtx.RepoRootPath != "" {
		rootPath = gitCtx.RepoRootPath
		gitCtx = gitctx.Collect(rootPath)
	}
	if abs, err := filepath.Abs(rootPath); err == nil {
		rootPath = abs
	}
	progress.Update(1, fmt.Sprintf("Resolved scan root: %s", rootPath))

	res, err := runMalscanEngine(malscanOptions{
		Root:           rootPath,
		IncludeHome:    includeHome,
		BinaryAnalysis: !noBinary,
		Depth:          depth,
		MaxFileSize:    maxFileSize,
		IOCFeeds:       !noFeeds,
		ConfigDir:      catalog,
		BadnetDir:      defsDir, // runtime overlay; badnet.LoadDir is a no-op if absent
		Progress:       progress.SetStage,
	})
	if err != nil {
		return err
	}
	progress.Update(2, fmt.Sprintf("Scanned %d target(s), inspected %d file(s)", len(res.Targets), res.FilesScanned))

	// Always persist the SARIF report. Default .vulnetix/malscan.sarif; --output-file overrides.
	warnOutputExtension(outputFile, ".sarif")
	outFile := outputFile
	if outFile == "" {
		outFile = filepath.Join(rootPath, ".vulnetix", "malscan.sarif")
	}
	progress.SetStage("Building SARIF report")
	sarifBytes, err := buildMalscanSARIFBytes(res, rootPath, gitCtx)
	if err != nil {
		return err
	}
	progress.Update(3, "Built SARIF report")
	progress.SetStage("Writing SARIF report")
	progressWriter := progress.Writer(os.Stderr)
	if err := writeMalscanFileTo(outFile, sarifBytes, progressWriter); err != nil {
		return err
	}
	progress.Update(4, fmt.Sprintf("Wrote SARIF report to %s", outFile))

	// Record findings and auto-resolve anything the engine no longer reports.
	// Memory always lives under the resolved scan root, never the process CWD.
	reconcileMalscanMemory(rootPath, gitCtx, res)

	// Upload (best-effort; community/unauthenticated callers are skipped).
	if !noUpload {
		progress.SetStage("Finalising results")
		uploadMalscanTo(res, gitCtx, progressWriter)
		progress.Update(5, "Finalisation step complete")
	} else {
		progress.Update(5, "Skipped upload by request")
	}

	// Terminal rendering (the SARIF file above is written regardless of format).
	progress.Complete("malware scan complete")
	progressComplete = true
	switch outputFmt {
	case "json":
		data, err := json.MarshalIndent(malscanJSONView(res), "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, string(data))
	case "sarif":
		fmt.Fprintln(os.Stdout, string(sarifBytes))
	default: // pretty / table
		renderMalscanPretty(res)
	}

	// Direct usage gates on findings: any malware → non-zero exit.
	if res.Malicious {
		count := len(res.Findings)
		return &MultiPolicyBreachError{Breaches: []GateBreach{{
			Gate:    "malware",
			Count:   count,
			Message: fmt.Sprintf("malscan: %s (%s)", pluralise("malware finding", count), res.MaliciousNote),
		}}}
	}
	return nil
}

// malscanDefinitionsDir is the per-user, persistent directory holding the
// runtime-refreshed badnet threat-intel definitions (bad-*.txt). It overrides via
// VULNETIX_MALSCAN_DEFS_DIR, else lives under the OS user-cache dir.
func malscanDefinitionsDir() string {
	if d := strings.TrimSpace(os.Getenv("VULNETIX_MALSCAN_DEFS_DIR")); d != "" {
		return d
	}
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "vulnetix", "malscan", "definitions")
}

// runFetchDefinitions downloads the upstream threat-intel feeds, rebuilds the
// local badnet definitions in dir, and reports a summary. It merges with any
// existing definitions so a transiently-unreachable feed never drops indicators.
// Subsequent `vulnetix malscan` runs load dir as an overlay on the engine's
// embedded set — so customers stay current between engine releases without
// recompiling malscan-engine.
func runFetchDefinitions(dir, feedsFile string) error {
	fmt.Fprintf(os.Stdout, "Fetching malscan threat-intel definitions → %s\n", dir)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var (
		set     *badnet.Set
		results []badnet.FeedResult
		err     error
	)
	if strings.TrimSpace(feedsFile) != "" {
		fmt.Fprintf(os.Stdout, "Using feed source mapping → %s\n", feedsFile)
		set, results, err = badnet.FetchWithFeedsFile(ctx, nil, feedsFile)
		if err != nil {
			return fmt.Errorf("load feeds file %s: %w", feedsFile, err)
		}
	} else {
		set, results = badnet.Fetch(ctx, nil)
	}
	ok, failed := 0, 0
	for _, r := range results {
		if r.OK {
			ok++
			fmt.Fprintf(os.Stdout, "  ok   %-30s ipv4=%-6d ipv6=%-4d domains=%-7d emails=%-6d\n",
				r.Name, r.IPv4, r.IPv6, r.Domains, r.Emails)
		} else {
			failed++
			fmt.Fprintf(os.Stderr, "  warn %-30s %s\n", r.Name, r.Err)
		}
	}
	if ok == 0 {
		return fmt.Errorf("no threat-intel feeds could be fetched (%d failed); definitions left unchanged", failed)
	}

	// Union with existing definitions (resilience against a partial fetch).
	if existing, err := badnet.LoadDir(dir); err == nil {
		set.Merge(existing)
	}
	changed, err := set.WriteFiles(dir)
	if err != nil {
		return fmt.Errorf("write definitions to %s: %w", dir, err)
	}
	v4, v6, d, e := set.Counts()
	fmt.Fprintf(os.Stdout, "Definitions updated: ipv4=%d ipv6=%d domains=%d emails=%d (%d files changed)\n", v4, v6, d, e, changed)
	fmt.Fprintf(os.Stdout, "%d feeds ok, %d failed — future `vulnetix malscan` runs will use these definitions.\n", ok, failed)

	// Also refresh the STIX side: force-refetch the vulnetix.com index/feeds AND
	// the TweetFeed base from remote (bypassing the tmp cache) and rewrite the
	// cache, so subsequent scans read fresh STIX definitions too. Offline/timeout
	// keeps the cached copy with a warning — never fatal.
	fmt.Fprintln(os.Stdout, "Refreshing STIX feeds (vulnetix index + TweetFeed)…")
	if warns, err := (&iocscan.FeedLoader{}).Refresh(); err != nil {
		fmt.Fprintf(os.Stderr, "  warn STIX refresh: %v (cached definitions retained)\n", err)
	} else {
		for _, w := range warns {
			fmt.Fprintf(os.Stderr, "  warn %-22s %s\n", w.Feed, w.Message)
		}
		fmt.Fprintf(os.Stdout, "STIX feeds refreshed (%d warning(s)).\n", len(warns))
	}
	return nil
}

// runMalscanEngine runs the full malscan-engine over every resolved ecosystem
// target and aggregates the findings, IOCs and samples. It never fails on a
// per-target error (those become warnings) so partial coverage still reports.
func runMalscanEngine(opts malscanOptions) (*malscanResult, error) {
	if opts.ConfigDir != "" {
		// config.Dir() honours MALSCAN_CONFIG_DIR; set it so per-ecosystem
		// capability overrides resolve from the caller's catalog dir.
		_ = os.Setenv("MALSCAN_CONFIG_DIR", opts.ConfigDir)
	}
	res := &malscanResult{Host: malscanHost()}
	reportMalscanProgress(opts, "Discovering dependency install targets")
	res.Targets = ecosystems.Resolve(opts.Root, opts.IncludeHome)
	if len(res.Targets) == 0 {
		reportMalscanProgress(opts, "No dependency install targets found")
	}

	maliciousLabels := map[string]bool{}
	manifestBudget := malscanMaxManifests

	for i, target := range res.Targets {
		reportMalscanProgress(opts, fmt.Sprintf("Scanning target %d/%d: %s %s", i+1, len(res.Targets), target.Ecosystem, target.Label))
		caps := capabilitiesFor(target.EngineSlug)

		// 1) STIX IOC filesystem scan (network-backed feeds).
		if opts.IOCFeeds {
			reportMalscanProgress(opts, fmt.Sprintf("Scanning IOCs %d/%d: %s", i+1, len(res.Targets), target.Label))
			scanTargetIOC(target, opts, res, maliciousLabels)
		}

		// 2/3/4) Per-package manifest detectors: detect.Detect + ioc.ExtractIOCs
		// + badhash over declared/candidate hashes. Bounded by manifestBudget.
		if manifestBudget > 0 {
			reportMalscanProgress(opts, fmt.Sprintf("Scanning manifests %d/%d: %s", i+1, len(res.Targets), target.Label))
			used := scanTargetManifests(target, caps, opts.Root, res, maliciousLabels, manifestBudget)
			manifestBudget -= used
			if manifestBudget <= 0 {
				res.Warnings = append(res.Warnings, fmt.Sprintf(
					"manifest detector cap (%d) reached — some installed packages were not pattern-analysed (iocscan still covered all files)",
					malscanMaxManifests))
			}
		}
	}

	res.Malicious = len(maliciousLabels) > 0
	res.MaliciousNote = malscanLabelSummary(maliciousLabels)
	return res, nil
}

func reportMalscanProgress(opts malscanOptions, stage string) {
	if opts.Progress != nil {
		opts.Progress(stage)
	}
}

// scanTargetIOC runs iocscan.Scan over one target and folds its evidence into
// the result (findings + IOCs + samples).
func scanTargetIOC(target ecosystems.Target, opts malscanOptions, res *malscanResult, malicious map[string]bool) {
	report, err := iocscan.Scan(iocscan.Options{
		Root:           target.Path,
		Ecosystem:      target.EngineSlug,
		Depth:          opts.Depth,
		BinaryAnalysis: opts.BinaryAnalysis,
		ContextLines:   iocscan.DefaultContextLines,
		MaxFileSize:    opts.MaxFileSize,
		SkipDirs:       ecosystems.ScanSkipDirs(),
		BadnetDir:      opts.BadnetDir,
	})
	if report != nil {
		res.FilesScanned += report.FilesScanned
		res.IndicatorCount += report.IndicatorCount
		for _, w := range report.Warnings {
			res.Warnings = append(res.Warnings, fmt.Sprintf("iocscan(%s): %s", target.EngineSlug, w.Message))
		}
	}
	if err != nil {
		// Feeds unavailable (offline) — degrade gracefully; detect/badhash still run.
		res.Warnings = append(res.Warnings, fmt.Sprintf("iocscan(%s): feeds unavailable: %v", target.EngineSlug, err))
		return
	}
	for _, ev := range report.Evidence {
		rel := relToRoot(opts.Root, ev.FilePath)
		desc := evidenceDescription(ev)
		cls := ev.Class
		if cls == "" {
			cls = detect.ClassEvidence
		}
		sev, level := classSeverity(cls)
		// Evidence-tier hits may be refined by the indicator's own severity (a
		// "high"-labelled IOC stays high rather than being forced to critical).
		// Demoted context hits — references in a dependency's test fixtures or
		// generated bundles — are pinned low regardless of indicator severity: the
		// file context, not the indicator, governs whether this occurrence signals.
		if cls == detect.ClassEvidence && ev.Indicator != nil && ev.Indicator.Severity != "" {
			sev = strings.ToLower(ev.Indicator.Severity)
		}
		snippet := malscanSnippet(ev)
		res.Findings = append(res.Findings, malscanFinding{
			RuleID:      "IOC-STIX-MATCH",
			Title:       "Known-bad IOC reference",
			Description: "A file references a known-bad indicator of compromise (domain, IP or URL) from the malscan STIX feeds.",
			Message:     desc,
			Severity:    sev,
			Level:       level,
			Ecosystem:   target.Ecosystem,
			File:        rel,
			StartLine:   ev.LineNumber,
			EndLine:     ev.LineNumber,
			Snippet:     snippet,
			CWEs:        cweNums(detect.DefaultMalwareCWE),
			Class:       string(cls),
			Category:    "ioc",
			Tags:        []string{"malware", "ioc", string(ev.IndicatorType)},
			Fingerprint: fingerprint("IOC-STIX-MATCH", rel, ev.IndicatorValue, strconv.Itoa(ev.LineNumber)),
			IOCType:     string(ev.IndicatorType),
			IOCValue:    ev.IndicatorValue,
		})
		res.IOCs = append(res.IOCs, malscanIOC{
			Type:       string(ev.IndicatorType),
			Value:      ev.IndicatorValue,
			Ecosystem:  target.EngineSlug,
			FilePath:   rel,
			RuleID:     "IOC-STIX-MATCH",
			Severity:   sev,
			References: indicatorRefs(ev),
			Sample:     sampleForFile(ev.FilePath),
		})
		// Only evidence-tier hits condemn the package/file for the malware gate;
		// demoted context hits are recorded for audit but never mark a target
		// malicious on their own.
		if cls == detect.ClassEvidence {
			malicious[malwareLabel(target.Ecosystem, rel)] = true
		}
	}
}

// malscanFindingRecords converts this run's malware findings into memory
// records keyed by the engine's fingerprint, which is already stable across
// runs (it hashes the rule, the relative path, the matched value and the line).
// The human-readable rule ID rides in Aliases so the VEX statement names the
// rule rather than a hex digest.
func malscanFindingRecords(res *malscanResult) map[string]memory.FindingRecord {
	if res == nil {
		return nil
	}
	out := make(map[string]memory.FindingRecord, len(res.Findings))
	for _, f := range res.Findings {
		rec := memory.FindingRecord{
			Aliases:   []string{f.RuleID},
			Severity:  f.Severity,
			Status:    "affected",
			Source:    "vulnetix-malscan",
			Ecosystem: f.Ecosystem,
		}
		if f.File != "" {
			rec.Locations = []memory.Location{{
				File:      f.File,
				StartLine: f.StartLine,
				EndLine:   f.EndLine,
				Snippet:   f.Snippet,
			}}
		}
		out[f.Fingerprint] = rec
	}
	return out
}

// reconcileMalscanMemory records this run's malware findings and resolves any
// prior finding the engine no longer reports, attesting the resolutions in
// .vulnetix/vex-malscan.openvex.json.
//
// Absence is proof enough: malscan re-walks every resolved dependency install
// directory on every run, so a finding that vanished means the artefact is gone
// or no longer matches the definitions. Location verification is not usable —
// package-level findings carry no file at all.
func reconcileMalscanMemory(rootPath string, gitCtx *gitctx.GitContext, res *malscanResult) {
	if disableMemory || res == nil {
		return
	}
	changes := reconcileStandalone(rootPath, gitCtx, memory.ToolMalscan,
		malscanFindingRecords(res), reconcileOptions{Mode: memory.ResolveOnAbsence})
	if vexPath, err := writeToolOpenVEX(rootPath, memory.ToolMalscan, changes); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: could not write malscan OpenVEX: %v\n", err)
	} else if vexPath != "" && !silent {
		fmt.Fprintf(os.Stderr, "  VEX: %s\n", vexPath)
	}
}

// runMalscanForGate is the entry point the scan/sca hooks use: it runs the engine
// and uploads, returning the malicious package/file labels so the caller can fold
// them into the malware quality gate. Best-effort: a nil result on error.
func runMalscanForGate(rootPath string, includeHome bool, gitCtx *gitctx.GitContext) (*malscanResult, []string) {
	res, err := runMalscanEngine(malscanOptions{
		Root:           rootPath,
		IncludeHome:    includeHome,
		BinaryAnalysis: true,
		IOCFeeds:       true,
	})
	if err != nil || res == nil {
		return nil, nil
	}
	// Persist the SARIF next to the other scan artefacts and upload.
	if sarifBytes, berr := buildMalscanSARIFBytes(res, rootPath, gitCtx); berr == nil {
		_ = writeMalscanFile(filepath.Join(rootPath, ".vulnetix", "malscan.sarif"), sarifBytes)
	}
	reconcileMalscanMemory(rootPath, gitCtx, res)
	uploadMalscan(res, gitCtx)

	var labels []string
	if res.Malicious {
		labels = malscanMaliciousLabels(res)
	}
	return res, labels
}

// shouldRunMalscanPass decides whether the scan/sca pipeline runs the in-process
// malscan pass. `scan` runs it by default; `sca` runs it only when block-malware
// is in effect; the focused SAST-family subcommands never run it. --no-malscan
// always disables it.
func shouldRunMalscanPass(cmd *cobra.Command, blockMalware bool) bool {
	if cmd == nil {
		return false
	}
	if noMal, err := cmd.Flags().GetBool("no-malscan"); err == nil && noMal {
		return false
	}
	switch cmd.Name() {
	case "scan":
		return true
	case "sca":
		return blockMalware
	default:
		return false
	}
}

// mergeMalscanBreach folds a malscan malware GateBreach into the scan's existing
// error. A nil breach is a no-op. A prior MultiPolicyBreachError gains the
// breach; a clean scan becomes one; any other (hard) error is preserved as-is
// and dominates.
func mergeMalscanBreach(scanErr error, breach *GateBreach) error {
	if breach == nil {
		return scanErr
	}
	if mpb, ok := scanErr.(*MultiPolicyBreachError); ok {
		mpb.Breaches = append(mpb.Breaches, *breach)
		return mpb
	}
	if scanErr == nil {
		return &MultiPolicyBreachError{Breaches: []GateBreach{*breach}}
	}
	return scanErr
}

// runMalscanPassForScan runs the malscan pass for the scan/sca pipeline (when
// applicable) and returns the malware GateBreach to merge — nil when malscan is
// not applicable, found nothing, or block-malware is not in effect. It always
// uploads findings when it runs; gating is separate from reporting.
func runMalscanPassForScan(cmd *cobra.Command, scanPath string, blockMalware bool, gitCtx *gitctx.GitContext) *GateBreach {
	if !shouldRunMalscanPass(cmd, blockMalware) {
		return nil
	}
	_, labels := runMalscanForGate(scanPath, false, gitCtx)
	if !blockMalware || len(labels) == 0 {
		return nil
	}
	breach := &GateBreach{
		Gate:  "malware",
		Count: len(labels),
		Message: fmt.Sprintf("--block-malware: malscan flagged %s: %s",
			pluralise("local artifact", len(labels)), strings.Join(labels, ", ")),
	}
	// The merged breach is appended after runLocalScan returns, so runLocalScan's
	// own breach-printing loop never shows it — print it here so the user sees
	// why the build failed (matches the "  ✗ <message>" gate style).
	if !silent {
		fmt.Fprintf(os.Stderr, "\n  ✗ %s\n", breach.Message)
	}
	return breach
}

// capabilitiesFor resolves the per-ecosystem capability map (embedded defaults
// overlaid with any operator override dir). A nil map means "all enabled".
func capabilitiesFor(slug string) map[string]bool {
	cfg, err := mconfig.ResolveDefault(slug)
	if err != nil || cfg == nil {
		return nil
	}
	return cfg.Capabilities
}

func malscanHost() iocscan.HostInfo {
	// iocscan stamps host info on its Report; reuse the same shape for a
	// detect/badhash-only run by borrowing a zero-evidence scan's host. Cheaper
	// to build directly:
	name, _ := os.Hostname()
	return iocscan.HostInfo{Hostname: name, OS: goos(), Arch: goarch(), PID: os.Getpid(), ScanTime: nowRFC3339()}
}

// malscanMaliciousLabels lists the malicious package/file labels for the gate.
func malscanMaliciousLabels(res *malscanResult) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range res.Findings {
		if f.Class != string(detect.ClassEvidence) {
			continue
		}
		label := f.File
		if label == "" {
			label = f.RuleID
		}
		if !seen[label] {
			seen[label] = true
			out = append(out, label)
		}
	}
	return out
}

func malscanLabelSummary(labels map[string]bool) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return ""
	}
	if len(keys) > 5 {
		return strings.Join(keys[:5], ", ") + fmt.Sprintf(" (+%d more)", len(keys)-5)
	}
	return strings.Join(keys, ", ")
}

func malwareLabel(ecosystem, rel string) string {
	if rel == "" {
		return ecosystem
	}
	return ecosystem + ":" + rel
}

// malscanJSONView is the -o json shape (findings + IOC metadata; samples are
// elided to keep the output readable — they live in the uploaded payload + SARIF).
func malscanJSONView(res *malscanResult) map[string]any {
	iocs := make([]map[string]any, 0, len(res.IOCs))
	for _, i := range res.IOCs {
		m := map[string]any{"type": i.Type, "value": i.Value, "ecosystem": i.Ecosystem, "file": i.FilePath}
		if len(i.References) > 0 {
			m["references"] = i.References
		}
		if i.Sample != nil {
			m["sampleSha256"] = i.Sample.SHA256
		}
		iocs = append(iocs, m)
	}
	return map[string]any{
		"host":           res.Host,
		"malicious":      res.Malicious,
		"filesScanned":   res.FilesScanned,
		"indicatorCount": res.IndicatorCount,
		"findings":       res.Findings,
		"iocs":           iocs,
		"warnings":       res.Warnings,
		"targets":        res.Targets,
	}
}

// sampleForFile reads the offending file (size-capped) for storage as an IOC
// sample. Returns nil when the file can't be read or is empty.
func sampleForFile(absPath string) *malscanSample {
	info, err := os.Stat(absPath)
	if err != nil || info.IsDir() || info.Size() == 0 {
		return nil
	}
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(data)
	if len(data) > malscanSampleMaxBytes {
		data = data[:malscanSampleMaxBytes]
	}
	return &malscanSample{
		SHA256:  hex.EncodeToString(sum[:]),
		Name:    filepath.Base(absPath),
		Content: data,
	}
}

// relToRoot returns absPath relative to root, falling back to the base name.
func relToRoot(root, absPath string) string {
	if rel, err := filepath.Rel(root, absPath); err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}
	return filepath.Base(absPath)
}

func fingerprint(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:16])
}

// cweNums extracts the integer ids from CWE strings like "CWE-506".
func cweNums(cwes ...string) []int {
	var out []int
	for _, c := range cwes {
		c = strings.TrimSpace(strings.ToUpper(c))
		c = strings.TrimPrefix(c, "CWE-")
		if n, err := strconv.Atoi(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func writeMalscanFile(path string, data []byte) error {
	return writeMalscanFileTo(path, data, os.Stderr)
}

func writeMalscanFileTo(path string, data []byte, w io.Writer) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if !silent {
		if w == nil {
			w = io.Discard
		}
		fmt.Fprintf(w, "Wrote malscan SARIF to %s\n", path)
	}
	return nil
}
