package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// ─────────────────────────────────────────────────────────────────────────
// jail.go — `vulnetix jail`, the pipeline gate over accumulated repo state.
//
// A repo is "jailed" when it breaches a policy-driven threshold: vulnerabilities
// past their remediation window, dependencies past end of life, strategic
// migrations that have not landed, hygiene categories that regressed.
//
// This is NOT the quality gate. `scan --severity`, `--block-eol` and friends
// decide whether a single scan's findings should break the build. Jail decides
// whether the repo — across every tool and category that has ever reported for
// it, over time — is in breach of the organisation's policy. The two answer
// different questions and stay separate.
//
// The server decides and the CLI renders. Policy semantics live once, next to
// the data, in one language. Shipping thresholds to the client is how the
// licence stage came to run a weaker fixed-policy fork of the real policy.
//
// CAPABILITY OWNERSHIP: runJailPipeline is the single entry point. Every
// subcommand here, and any future in-pipeline caller such as `scan --jail`,
// reaches the gate through this one options struct and this one function.
// Nothing else in cmd/ may call client.CliJail directly.
// ─────────────────────────────────────────────────────────────────────────

// JailVerdictError is returned when the gate reports jailed or indeterminate.
//
// The command has already rendered the full verdict block, so Execute()
// suppresses the generic "Error:" line for it the same way it does for a
// quality-gate breach.
type JailVerdictError struct {
	Verdict string
	Code    int
	Summary vdb.CliJailSummary
}

func (e *JailVerdictError) Error() string {
	if e.Verdict == vdb.JailVerdictIndeterminate {
		return fmt.Sprintf("jail could not be evaluated: %s",
			pluralise("rule", e.Summary.Indeterminate)+" lacked current scan coverage")
	}
	return fmt.Sprintf("repository is jailed: %s breached",
		pluralise("policy rule", e.Summary.Breaches))
}

// ExitCode reports 1 for a breach and 3 for an indeterminate verdict.
func (e *JailVerdictError) ExitCode() int { return e.Code }

// JailUsageError is a local argument or configuration failure: an unparseable
// duration, a scope override on an assess run, an unwritable artefact path, no
// credentials.
//
// Its exit code 2 is deliberately scoped to this command. Cobra's own usage
// errors across the rest of the tree keep exiting 1; promoting them globally
// would change the contract of every pipeline in the field.
type JailUsageError struct{ err error }

func (e *JailUsageError) Error() string { return e.err.Error() }
func (e *JailUsageError) Unwrap() error { return e.err }
func (e *JailUsageError) ExitCode() int { return ExitUsage }

func jailUsage(format string, a ...any) error {
	return &JailUsageError{err: fmt.Errorf(format, a...)}
}

// Jail modes.
const (
	jailModeAssess  = ""
	jailModeExplain = "explain"
	jailModeList    = "list"
	jailModeExempt  = "exempt"
)

// jailDefaultTimeout bounds the gate. A pipeline waiting on a policy decision
// should not wait three minutes for one.
const jailDefaultTimeout = 60 * time.Second

// JailRunOptions is the single input to the jail capability.
type JailRunOptions struct {
	Mode string

	RootPath  string
	Repo      string
	Branch    string
	RuleUuids []string

	// KnownSnapshotUuids names scanner runs the caller just created, so a
	// scan-then-gate in one invocation is not defeated by read-replica lag.
	KnownSnapshotUuids []string

	// Artefacts
	VexPath    string
	VexFormat  string
	SarifPath  string
	WriteVex   bool
	WriteSarif bool

	// Gate behaviour
	NoFail          bool
	StalenessDays   int
	OnStale         string
	MaxLookbackDays int

	// Exempt mode
	ExemptRuleUuid         string
	ExemptReason           string
	ExemptExpires          time.Duration
	ExemptDeactivate       string
	ExemptDeactivateReason string

	BaseURL string
	Output  string
	Timeout time.Duration
	Stdout  io.Writer
	Stderr  io.Writer
}

// JailRunResult is what the caller needs to render and to decide an exit code.
type JailRunResult struct {
	Response  *vdb.CliJailResponse
	Exemption *vdb.CliJailExemptResponse
	Artefacts []string
	ExitCode  int
}

// runJailPipeline is the jail capability's one entry function.
//
// It never calls os.Exit and never prints the final verdict line — the caller
// owns both, so an in-pipeline composition such as `scan --jail` can use the
// gate without inheriting its process semantics or duplicating its output.
func runJailPipeline(ctx context.Context, opts JailRunOptions) (*JailRunResult, error) {
	if err := validateJailOptions(&opts); err != nil {
		return nil, err
	}

	client := newCliClient()
	if client == nil {
		return nil, jailUsage("authentication required: run 'vulnetix auth login' to authenticate")
	}
	if opts.BaseURL != "" {
		client.BaseURL = opts.BaseURL
	}

	env := envForCliWithGit(jailGitContext(opts.RootPath))

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = jailDefaultTimeout
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if opts.Mode == jailModeExempt {
		return runJailExempt(callCtx, client, env, opts)
	}

	req := vdb.CliJailRequest{
		Mode:               opts.Mode,
		Repo:               opts.Repo,
		Branch:             opts.Branch,
		RuleUuids:          opts.RuleUuids,
		KnownSnapshotUuids: opts.KnownSnapshotUuids,
		IncludeVex:         opts.WriteVex,
		IncludeSarif:       opts.WriteSarif,
		StalenessDays:      opts.StalenessDays,
		OnStale:            opts.OnStale,
		MaxLookbackDays:    opts.MaxLookbackDays,
	}

	resp, err := client.CliJail(callCtx, env, req)
	if err != nil {
		return nil, fmt.Errorf("jail evaluation failed: %w", err)
	}

	result := &JailRunResult{Response: &resp.Data, ExitCode: resp.Data.ExitCode}

	// Artefacts are written before the verdict is returned, deliberately. A red
	// gate is exactly when somebody needs the evidence, so the evidence must not
	// be conditional on the gate passing.
	if opts.WriteVex {
		path, werr := writeJailVEX(&resp.Data, opts.VexPath, opts.VexFormat)
		if werr != nil {
			return result, werr
		}
		if path != "" {
			result.Artefacts = append(result.Artefacts, path)
		}
	}
	if opts.WriteSarif {
		path, werr := writeJailSARIF(&resp.Data, opts.SarifPath)
		if werr != nil {
			return result, werr
		}
		if path != "" {
			result.Artefacts = append(result.Artefacts, path)
		}
	}

	// --no-fail is the adoption escape hatch: report everything, gate nothing.
	if opts.NoFail {
		result.ExitCode = ExitOK
	}

	return result, nil
}

func runJailExempt(ctx context.Context, client *vdb.Client, env vdb.CliEnv, opts JailRunOptions) (*JailRunResult, error) {
	req := vdb.CliJailExemptRequest{
		RuleUuid:         opts.ExemptRuleUuid,
		Repo:             opts.Repo,
		Reason:           opts.ExemptReason,
		Deactivate:       opts.ExemptDeactivate,
		DeactivateReason: opts.ExemptDeactivateReason,
	}
	if opts.ExemptExpires > 0 {
		req.ExpiresAt = time.Now().Add(opts.ExemptExpires).UnixMilli()
	}
	resp, err := client.CliJailExempt(ctx, env, req)
	if err != nil {
		return nil, fmt.Errorf("jail exemption failed: %w", err)
	}
	return &JailRunResult{Exemption: &resp.Data, ExitCode: ExitOK}, nil
}

// validateJailOptions rejects every local mistake BEFORE any network work, the
// way --dry-run is handled across the scan family. A pipeline that misconfigured
// the gate should learn so immediately, not after a round trip.
func validateJailOptions(opts *JailRunOptions) error {
	switch opts.Mode {
	case jailModeAssess, jailModeExplain, jailModeList, jailModeExempt:
	default:
		return jailUsage("unknown jail mode %q", opts.Mode)
	}

	// Scope overrides are an inspection affordance. Honouring them on an assess
	// run would let a pipeline point its own gate at a clean repo.
	if opts.Mode == jailModeAssess && (opts.Repo != "" || opts.Branch != "") {
		return jailUsage("--repo and --branch are only available on 'jail explain' and 'jail list'")
	}

	switch strings.ToLower(opts.VexFormat) {
	case "", "openvex", "cyclonedx", "cyclonedx-json":
	default:
		return jailUsage("--vex-format must be one of: openvex, cyclonedx")
	}

	if opts.OnStale != "" {
		switch strings.ToLower(opts.OnStale) {
		case "fail", "warn", "pass":
		default:
			return jailUsage("--on-stale must be one of: fail, warn, pass")
		}
	}

	if opts.StalenessDays < 0 {
		return jailUsage("--staleness-days must not be negative")
	}
	if opts.MaxLookbackDays < 0 {
		return jailUsage("--max-lookback-days must not be negative")
	}

	if opts.Mode == jailModeExempt {
		if opts.ExemptDeactivate == "" && strings.TrimSpace(opts.ExemptReason) == "" {
			return jailUsage("--reason is required to create an exemption")
		}
	}

	if opts.Output != "" {
		switch strings.ToLower(opts.Output) {
		case "pretty", "json":
		default:
			return jailUsage("--output must be one of: pretty, json")
		}
	}

	return nil
}

func jailGitContext(rootPath string) *gitctx.GitContext {
	path := rootPath
	if path == "" {
		path, _ = os.Getwd()
	}
	if path == "" {
		return nil
	}
	return gitctx.Collect(path)
}

// ─────────────────────────────────────────────────────────────────────────
// Command tree
// ─────────────────────────────────────────────────────────────────────────

func newJailCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jail",
		Short: "Gate this pipeline against the organisation's jail policy",
		Long: `Assess this repository against the organisation's jail policy and gate the
pipeline on the result.

A repository is "jailed" when it breaches a policy-driven threshold over its
ACCUMULATED state — vulnerabilities past their remediation window, dependencies
past end of life, strategic migrations that have not landed, hygiene categories
that regressed. That is a different question from the one 'vulnetix scan'
answers, which is whether a single scan's findings should break this build.

The organisation's policy is evaluated server-side against the latest scan
result per tool, per category. Historical scans are collapsed away: a repo
scanned nightly for a year contributes one result per tool, not 365.

Exit codes:
  0  clear
  1  jailed — at least one rule breached
  2  usage or configuration error
  3  indeterminate — the backend state needed to decide is stale or missing

Exit 3 is deliberately distinct from exit 1. "You breached policy" is fixed by a
developer; "your scan stage stopped running" is fixed by whoever owns the CI
configuration, and a gate that reported them the same way would send every
failure to the wrong person.`,
		Args: cobra.NoArgs,
		PersistentPreRunE: func(c *cobra.Command, _ []string) error {
			printBanner(c)
			return resolveVDBCredentials(false)
		},
		RunE: func(c *cobra.Command, _ []string) error { return runJailCmd(c, jailModeAssess) },
	}

	addJailFlags(cmd)
	addJailGateFlags(cmd)

	cmd.AddCommand(newJailExplainCommand())
	cmd.AddCommand(newJailListCommand())
	cmd.AddCommand(newJailExemptCommand())
	return cmd
}

func newJailExplainCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain",
		Short: "Show why the repository is or is not jailed, rule by rule",
		Long: `Report every rule's verdict with the matched items behind it, without
producing artefacts or moving the ratchet baseline.

Every enabled rule is evaluated on every run — rule order decides presentation
and which rule supplies the headline reason, never which rules are checked. A
first-match-wins gate would show a subset of the truth, which is the one thing
this command exists to prevent.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error { return runJailCmd(c, jailModeExplain) },
	}
	addJailFlags(cmd)
	return cmd
}

func newJailListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Show the jail policy in effect for this repository",
		Long: `Show the resolved jail policy — the rules in effect, their thresholds, and
their current observed values — without gating.

A per-repository policy overrides the organisation default outright when one
exists; the reported source says which applied.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error { return runJailCmd(c, jailModeList) },
	}
	addJailFlags(cmd)
	return cmd
}

func newJailExemptCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exempt",
		Short: "Create or retire a time-boxed exemption for this repository",
		Long: `Waive one rule, or the whole policy, for this repository until a date.

Exemptions expire by design. A permanent waiver is a policy change and belongs
in the policy, where somebody can see it.

An exemption never rewrites the evidence: the verdict still reports the real
observed value, the threshold, that the rule would have breached, and which
exemption suppressed it.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error { return runJailCmd(c, jailModeExempt) },
	}
	addJailFlags(cmd)
	cmd.Flags().String("rule", "", "Rule UUID to exempt (omit to exempt every rule in the policy)")
	cmd.Flags().String("reason", "", "Why this exemption exists (required, recorded in the audit trail)")
	cmd.Flags().Duration("expires", 30*24*time.Hour, "How long the exemption lasts")
	cmd.Flags().String("deactivate", "", "Retire an existing exemption by UUID instead of creating one")
	cmd.Flags().String("deactivate-reason", "", "Why the exemption is being retired")
	return cmd
}

// addJailFlags registers the flags every jail mode honours.
func addJailFlags(cmd *cobra.Command) {
	cmd.Flags().String("path", ".", "Repository path to derive identity from")
	cmd.Flags().String("repo", "", "Repository to assess (explain and list only)")
	cmd.Flags().String("branch", "", "Branch to assess (explain and list only)")
	cmd.Flags().StringArray("rule-uuid", nil, "Restrict evaluation to specific rule UUIDs (repeatable)")
	cmd.Flags().String("base-url", "", "VDB API base URL")
	cmd.Flags().StringP("output", "o", "pretty", "Output format (pretty, json)")
	cmd.Flags().Duration("timeout", jailDefaultTimeout, "Maximum time to wait for the gate")
	cmd.Flags().Int("max-lookback-days", 0, "How far back to consider scan coverage (0 = server default)")
	_ = cmd.RegisterFlagCompletionFunc("output", cobra.FixedCompletions([]string{"pretty", "json"}, cobra.ShellCompDirectiveNoFileComp))
	_ = cmd.MarkFlagDirname("path")
}

// addJailGateFlags registers the flags that only make sense when gating.
func addJailGateFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("no-fail", false, "Report the verdict but always exit 0")
	cmd.Flags().String("on-stale", "", "Override the policy's staleness posture (fail, warn, pass) — tightening only")
	cmd.Flags().Int("staleness-days", 0, "Override the policy's staleness window — tightening only")
	cmd.Flags().String("vex-out", defaultJailVEXPath, "Where to write the VEX document")
	cmd.Flags().String("vex-format", "openvex", "VEX format (openvex, cyclonedx)")
	cmd.Flags().String("sarif-out", defaultJailSARIFPath, "Where to write the SARIF document")
	cmd.Flags().Bool("no-artefacts", false, "Do not write the VEX or SARIF documents")
	_ = cmd.RegisterFlagCompletionFunc("on-stale", cobra.FixedCompletions([]string{"fail", "warn", "pass"}, cobra.ShellCompDirectiveNoFileComp))
	_ = cmd.RegisterFlagCompletionFunc("vex-format", cobra.FixedCompletions([]string{"openvex", "cyclonedx"}, cobra.ShellCompDirectiveNoFileComp))
}

// jailOptionsFromCommand is the single flags-to-options translation. Every mode
// goes through it so a flag cannot mean one thing on `jail` and another on
// `jail explain`.
func jailOptionsFromCommand(cmd *cobra.Command, mode string) JailRunOptions {
	opts := JailRunOptions{
		Mode:    mode,
		Stdout:  cmd.OutOrStdout(),
		Stderr:  cmd.ErrOrStderr(),
		VexPath: defaultJailVEXPath,
	}

	opts.RootPath, _ = cmd.Flags().GetString("path")
	opts.Repo, _ = cmd.Flags().GetString("repo")
	opts.Branch, _ = cmd.Flags().GetString("branch")
	opts.RuleUuids, _ = cmd.Flags().GetStringArray("rule-uuid")
	opts.BaseURL, _ = cmd.Flags().GetString("base-url")
	opts.Output, _ = cmd.Flags().GetString("output")
	opts.Timeout, _ = cmd.Flags().GetDuration("timeout")
	opts.MaxLookbackDays, _ = cmd.Flags().GetInt("max-lookback-days")

	// Gate-only flags exist on the bare command; the inspection subcommands do
	// not register them and must not silently inherit a stale value.
	if f := cmd.Flags().Lookup("no-fail"); f != nil {
		opts.NoFail, _ = cmd.Flags().GetBool("no-fail")
		opts.OnStale, _ = cmd.Flags().GetString("on-stale")
		opts.StalenessDays, _ = cmd.Flags().GetInt("staleness-days")
		opts.VexPath, _ = cmd.Flags().GetString("vex-out")
		opts.VexFormat, _ = cmd.Flags().GetString("vex-format")
		opts.SarifPath, _ = cmd.Flags().GetString("sarif-out")

		noArtefacts, _ := cmd.Flags().GetBool("no-artefacts")
		opts.WriteVex = !noArtefacts
		opts.WriteSarif = !noArtefacts
	}

	if f := cmd.Flags().Lookup("reason"); f != nil {
		opts.ExemptRuleUuid, _ = cmd.Flags().GetString("rule")
		opts.ExemptReason, _ = cmd.Flags().GetString("reason")
		opts.ExemptExpires, _ = cmd.Flags().GetDuration("expires")
		opts.ExemptDeactivate, _ = cmd.Flags().GetString("deactivate")
		opts.ExemptDeactivateReason, _ = cmd.Flags().GetString("deactivate-reason")
	}

	return opts
}

func runJailCmd(cmd *cobra.Command, mode string) error {
	opts := jailOptionsFromCommand(cmd, mode)

	switch strings.ToLower(opts.Output) {
	case "", "pretty":
		initDisplayContext(cmd, display.ModeText)
	case "json":
		initDisplayContext(cmd, display.ModeJSON)
	default:
		return jailUsage("--output must be one of: pretty, json")
	}

	result, err := runJailPipeline(cmd.Context(), opts)
	if err != nil {
		// A verdict that was reached and then failed to write its artefacts
		// still deserves to be shown; the write error is what is returned.
		if result != nil && result.Response != nil {
			renderJailResult(cmd, result, opts)
		}
		return err
	}

	renderJailResult(cmd, result, opts)

	if opts.Mode == jailModeExempt {
		return nil
	}

	// explain and list are inspection commands and never gate. A developer
	// asking "why" should not have their shell exit non-zero for answering.
	if opts.Mode != jailModeAssess {
		return nil
	}

	if result.ExitCode == ExitOK {
		return nil
	}
	return &JailVerdictError{
		Verdict: result.Response.Verdict,
		Code:    result.ExitCode,
		Summary: result.Response.Summary,
	}
}

// jailVerdictErrorFrom builds the gate's typed error from a result, for callers
// that compose the gate rather than run it as a command.
func jailVerdictErrorFrom(result *JailRunResult) error {
	if result == nil || result.Response == nil || result.ExitCode == ExitOK {
		return nil
	}
	return &JailVerdictError{
		Verdict: result.Response.Verdict,
		Code:    result.ExitCode,
		Summary: result.Response.Summary,
	}
}

// isJailVerdictError reports whether err is a jail verdict, for callers that
// need to distinguish a gate decision from a transport failure.
func isJailVerdictError(err error) bool {
	var jv *JailVerdictError
	return errors.As(err, &jv)
}

func init() { rootCmd.AddCommand(newJailCommand()) }
