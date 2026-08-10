// Package scanopts builds a pipeline.Options from a cobra command's flags.
//
// It exists so there is exactly one place that knows how a scan-family flag
// becomes an analysis input. The language server never calls it: it fills
// pipeline.Options from LSP client settings instead. That is the point of the
// split, and it is why this package depends on cobra while internal/pipeline
// does not.
package scanopts

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vulnetix/cli/v3/internal/pipeline"
	"github.com/vulnetix/cli/v3/internal/sast"
	"github.com/vulnetix/cli/v3/internal/scan"
)

// FromCommand reads every scan-family flag that maps directly onto an analysis
// input and returns the corresponding pipeline.Options.
//
// It covers only what the flags alone determine. Four groups of fields are
// deliberately left zero for the caller to fill, because the flags do not
// decide them:
//
//   - Files, GitCtx, SysInfo, SeedBOM, VulnetixSeedBOM — discovered by
//     detection and collection passes that run after flag parsing.
//   - The No* feature booleans — derived from the --evaluate-*/--no-* toggles
//     together with the invoking command's identity.
//   - LockedKinds — specializedRuleKinds(cmd.Name()).
//   - RespectGitignore — computed from the --*-include-ignored family, whose
//     policy differs per command.
//
// The gate fields (severity, exploits, block-*, version-lag, cooldown) are
// populated here but may be overwritten afterwards by org quality-gate policy,
// which always wins, even over an explicitly passed flag. That override must
// happen after this call and before any of those values is consumed.
//
// Validation that would otherwise be duplicated per command lives here:
// --severity and --exploits are normalised and checked against the canonical
// lists, so an invalid value fails before any work starts rather than being
// silently ignored deep in a stage.
func FromCommand(cmd *cobra.Command) (pipeline.Options, error) {
	var opts pipeline.Options
	flags := cmd.Flags()

	getBool := func(name string) bool { v, _ := flags.GetBool(name); return v }
	getInt := func(name string) int { v, _ := flags.GetInt(name); return v }
	getString := func(name string) string { v, _ := flags.GetString(name); return v }
	getStrings := func(name string) []string { v, _ := flags.GetStringArray(name); return v }

	opts.RootPath = getString("path")
	if opts.RootPath == "" {
		opts.RootPath = "."
	}
	opts.Depth = getInt("depth")
	opts.Excludes = getStrings("exclude")
	opts.NoProgress = getBool("no-progress")

	// --paths is the deprecated spelling; either one enables the behaviour.
	opts.ShowPaths = getBool("show-introduced-paths") || getBool("paths")

	opts.NoExploits = getBool("no-exploits")
	opts.NoRemediation = getBool("no-remediation")
	opts.ResultsOnly = getBool("results-only")
	opts.DryRun = getBool("dry-run")

	opts.BlockMalware = getBool("block-malware")
	opts.BlockEOL = getBool("block-eol")
	opts.BlockUnpinned = getBool("block-unpinned")
	opts.VersionLag = getInt("version-lag")
	opts.CooldownDays = getInt("cooldown")

	severity, err := NormaliseSeverity(getString("severity"))
	if err != nil {
		return pipeline.Options{}, err
	}
	opts.SeverityThreshold = severity

	exploits, err := NormaliseExploits(getString("exploits"))
	if err != nil {
		return pipeline.Options{}, err
	}
	opts.ExploitThreshold = exploits

	opts.IgnoreGlobs = getStrings("ignore")
	opts.IgnoreGit = getBool("ignore-git")
	opts.IgnoreBinaries = getBool("ignore-binaries")
	opts.GitHistory = getBool("git-history")
	opts.GitHistoryMaxCommits = getInt("git-history-max-commits")
	opts.GitHistoryMaxFiles = getInt("git-history-max-files")

	opts.SCAAutofix = getBool("sca-autofix")

	opts.License = pipeline.LicensePolicy{
		Mode:      getString("license-mode"),
		AllowCSV:  getString("allow"),
		AllowFile: getString("allow-file"),
	}

	// SAST flags. sca registers none of these, so every read is guarded by the
	// flag's existence rather than assuming the whole family carries them.
	opts.DisableDefaultRules = getBool("disable-default-rules")
	opts.RuleRegistry = getString("rule-registry")
	if opts.RuleRegistry == "" {
		opts.RuleRegistry = sast.DefaultRegistry
	}
	opts.RuleID = strings.ToUpper(strings.TrimSpace(getString("rule-id")))

	// -1 means "choose a width from the finding span"; an explicitly passed 0
	// disables snippets. Only an explicit --snippet-context overrides the
	// default, which is why this checks Changed rather than reading the value.
	opts.SnippetContext = -1
	if flags.Changed("snippet-context") {
		opts.SnippetContext = getInt("snippet-context")
	}

	refs, err := ParseRuleRefs(getStrings("rule"))
	if err != nil {
		return pipeline.Options{}, err
	}
	opts.RuleRefs = refs

	return opts, nil
}

// NormaliseSeverity lower-cases and validates a --severity value. An empty
// value means "no severity gate" and is returned unchanged.
func NormaliseSeverity(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "", nil
	}
	for _, valid := range scan.ValidSeverityThresholds {
		if value == valid {
			return value, nil
		}
	}
	return "", fmt.Errorf("invalid --severity %q: must be one of: %s",
		value, strings.Join(scan.ValidSeverityThresholds, ", "))
}

// NormaliseExploits lower-cases and validates an --exploits value. An empty
// value means "no exploit gate" and is returned unchanged.
func NormaliseExploits(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "", nil
	}
	for _, valid := range scan.ValidExploitThresholds {
		if value == valid {
			return value, nil
		}
	}
	return "", fmt.Errorf("invalid --exploits %q: must be one of: %s",
		value, strings.Join(scan.ValidExploitThresholds, ", "))
}

// ParseRuleRefs turns --rule arguments into sast.RuleRefs, failing on the first
// malformed reference rather than silently dropping it.
func ParseRuleRefs(args []string) ([]sast.RuleRef, error) {
	var refs []sast.RuleRef
	for _, arg := range args {
		ref, err := sast.ParseRuleRef(arg)
		if err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	return refs, nil
}
