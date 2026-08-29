package pipeline

import (
	"github.com/vulnetix/cli/v3/internal/cdx"
	"github.com/vulnetix/cli/v3/internal/fix"
	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/internal/sast"
	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/internal/triage"
)

// Options is everything an analysis run needs, as named fields.
//
// This replaces the 40 positional parameters cmd/runLocalScan used to take, a
// signature where `true, noSCA, true, true, true` was a real call site and
// adding a parameter meant touching every caller. More importantly it is the
// entry point AGENTS.md asks for: one options struct that both the scan
// subcommands and the language server fill in, so neither owns a private
// version of "what a scan is".
//
// Deliberately absent: anything about presentation. Where results are written,
// how they are rendered, and whether there is a terminal at all are the
// caller's business. Progress and log output go through Reporter.
type Options struct {
	// ── Target ──────────────────────────────────────────────────────────────

	// Files are the manifests and SBOMs already detected under RootPath. The
	// caller runs detection so it can report and filter before committing to a
	// scan.
	Files []scan.DetectedFile

	// RootPath is the absolute directory being analysed.
	RootPath string

	// Depth bounds directory recursion during manifest detection (--depth).
	Depth int

	// Excludes are glob patterns removed from the walk (--exclude).
	Excludes []string

	// Deployment labels where these results are deployed and who owns them
	// (--project/--cluster/--namespace/--environment/--tag). It is inert for
	// the analysis itself — nothing branches on it — and exists so the labels
	// reach the CycloneDX metadata and the upload envelope, where the server
	// can join results across repositories. See internal/cdx/deployment.go.
	Deployment cdx.DeploymentContext

	// VEXFiles are third-party VEX documents to apply to the findings before
	// the quality gates are evaluated (--vex-file). Empty when --no-vex was
	// passed, so the engine has one thing to check rather than two.
	VEXFiles []string

	// ── Feature toggles ─────────────────────────────────────────────────────
	//
	// Negative names throughout, matching the flags they come from. The scan
	// engine branches on these booleans and never on a command name; the three
	// deliberate name-keyed exceptions live in the caller (see AGENTS.md).

	NoSCA        bool
	NoSASTRules  bool
	NoSecrets    bool
	NoContainers bool
	NoIAC        bool
	NoLicenses   bool

	// NoExploits and NoRemediation drop the corresponding VDB enrichment
	// passes; the SCA lookup itself still runs.
	NoExploits    bool
	NoRemediation bool

	// ── Quality gate ────────────────────────────────────────────────────────
	//
	// A breach makes the run return a *BreachError, which the CLI turns into
	// exit code 1. These may be overwritten by org policy before the run
	// starts: an org quality gate always wins, even over an explicit flag.

	// SeverityThreshold is validated against scan.ValidSeverityThresholds.
	SeverityThreshold string
	// ExploitThreshold is validated against scan.ValidExploitThresholds.
	ExploitThreshold string
	BlockMalware     bool
	BlockEOL         bool
	BlockUnpinned    bool
	VersionLag       int
	CooldownDays     int

	// Jail runs the organisation's jail policy against this repository after the
	// scan has uploaded, and gates on the verdict.
	//
	// Unlike the thresholds above, which grade THIS run's findings, the jail
	// policy grades the repository's accumulated state across every tool and
	// category that has reported for it. A breach exits 1 alongside the other
	// gates; a rule that cannot be evaluated against current scan coverage exits
	// 3, which is a different problem with a different owner.
	Jail bool

	// ── Rego rules ──────────────────────────────────────────────────────────

	// DisableDefaultRules drops the embedded corpus, leaving only RuleRefs.
	DisableDefaultRules bool
	// RuleRefs are external rule packs, cloned from RuleRegistry.
	RuleRefs []sast.RuleRef
	// RuleRegistry defaults to sast.DefaultRegistry when empty.
	RuleRegistry string
	// RuleID restricts the run to a single VNX-NNNN rule.
	RuleID string
	// LockedKinds restricts the run to these rule kinds, embedded and external
	// alike. Nil means "no lock", which is the generic scan command's
	// behaviour. The language server sets this per trigger: the keystroke path
	// runs sast/iac/oci only, because the 1,092 secrets rules cost roughly 20x
	// what every other kind costs combined.
	LockedKinds []string
	// SnippetContext shapes SARIF snippets: -1 picks a width from the finding
	// span, 0 disables snippets.
	SnippetContext int

	// Reachability selects the tree-sitter reachability mode applied to the
	// CVEs the SCA pass produces: "direct" scans only each vulnerable
	// package's installed directory, "transitive" sweeps the rest of the
	// project for callers, "both" does both, and "off" skips the analysis (and
	// the server-side query fetch) entirely. Empty means "both".
	//
	// It is a string rather than a reachability.Mode so internal/pipeline stays
	// free of the CGo tree-sitter dependency; the value is validated by
	// internal/scanopts before it gets here.
	Reachability string

	// ── Walk and secrets-stage options ──────────────────────────────────────
	//
	// These only affect the SAST engine when the secrets kind is enabled; other
	// kinds ignore them. Threaded explicitly so the secrets subcommand can turn
	// on binary and git-history inspection without changing generic scans.

	IgnoreGlobs          []string
	IgnoreGit            bool
	IgnoreBinaries       bool
	GitHistory           bool
	GitHistoryMaxCommits int
	GitHistoryMaxFiles   int
	// RespectGitignore prunes files matched by .gitignore.
	RespectGitignore bool

	// ── Remediation ─────────────────────────────────────────────────────────

	SCAAutofix     bool
	SCAAutofixOpts fix.Options
	// AutofixResolved carries findings a previous autofix pass fixed, so the
	// confirmation re-scan can mark them resolved rather than re-reporting.
	AutofixResolved []*triage.TriageFinding

	// ── Licence policy ──────────────────────────────────────────────────────

	License LicensePolicy

	// ── Context and seeds ───────────────────────────────────────────────────

	GitCtx  *gitctx.GitContext
	SysInfo *gitctx.SystemInfo
	// SeedBOM and VulnetixSeedBOM carry components from an existing SBOM into
	// the produced document, so a scan never loses what a previous one found.
	SeedBOM         *cdx.BOM
	VulnetixSeedBOM *cdx.BOM

	// ── Run modifiers ───────────────────────────────────────────────────────

	// There is deliberately no Concurrency field. --concurrency was carried
	// through the whole engine without being read; SCA fan-out is governed by
	// VULNETIX_SCA_CONCURRENCY. Adding a field here for a value nothing
	// consumes is how that gap survived for as long as it did.

	// ShowPaths includes the dependency chain that introduced each package.
	ShowPaths bool
	// ResultsOnly suppresses all output when the run is clean.
	ResultsOnly bool
	// DryRun performs detection, parsing and memory reads with zero API calls.
	DryRun bool
	// NoProgress suppresses the live progress row. Kept here because it also
	// reaches callees that build their own display contexts.
	NoProgress bool
}

// LicensePolicy is the licence policy as the scan-family flags express it,
// handed to the licence owner (runLicensePipeline) when that stage runs.
type LicensePolicy struct {
	// Mode is "inclusive" or "individual".
	Mode string
	// AllowCSV is a comma-separated SPDX allowlist.
	AllowCSV string
	// AllowFile is a path to a newline-separated SPDX allowlist.
	AllowFile string
	// PolicyFile and ExceptionsFile are the declarative forms of the same
	// decision: a category-based policy and its approved exceptions. Empty
	// means "discover the default path under the scanned root, and fall back to
	// the built-in policy" — so a project that has neither behaves exactly as
	// it did before they existed.
	PolicyFile     string
	ExceptionsFile string
}
