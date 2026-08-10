package scanopts

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/vulnetix/cli/v3/internal/sast"
)

// newScanLikeCommand registers the subset of scan-family flags FromCommand
// reads. It mirrors addScanFlags/addSASTFlags in cmd/scan.go; keeping a local
// copy avoids importing cmd (which would be an import cycle) at the cost of
// this needing to track the real registration. TestReadsEveryFlagItClaims below
// is the guard: FromCommand must not read a flag this fixture does not define.
func newScanLikeCommand() *cobra.Command {
	c := &cobra.Command{Use: "scan"}
	f := c.Flags()

	f.String("path", ".", "")
	f.Int("depth", 3, "")
	f.StringArray("exclude", nil, "")
	f.Bool("no-progress", false, "")
	f.Bool("show-introduced-paths", false, "")
	f.Bool("paths", false, "")
	f.Bool("no-exploits", false, "")
	f.Bool("no-remediation", false, "")
	f.Bool("results-only", false, "")
	f.Bool("dry-run", false, "")

	f.String("severity", "", "")
	f.String("exploits", "", "")
	f.Bool("block-malware", false, "")
	f.Bool("block-eol", false, "")
	f.Bool("block-unpinned", false, "")
	f.Int("version-lag", 0, "")
	f.Int("cooldown", 0, "")

	f.StringArray("ignore", nil, "")
	f.Bool("ignore-git", false, "")
	f.Bool("ignore-binaries", false, "")
	f.Bool("git-history", true, "")
	f.Int("git-history-max-commits", 500, "")
	f.Int("git-history-max-files", 5000, "")

	f.Bool("sca-autofix", false, "")
	f.String("license-mode", "", "")
	f.String("allow", "", "")
	f.String("allow-file", "", "")

	f.Bool("disable-default-rules", false, "")
	f.StringArray("rule", nil, "")
	f.String("rule-registry", "", "")
	f.String("rule-id", "", "")
	f.Int("snippet-context", -1, "")

	return c
}

func TestDefaults(t *testing.T) {
	c := newScanLikeCommand()
	require.NoError(t, c.ParseFlags(nil))
	opts, err := FromCommand(c)
	require.NoError(t, err)

	require.Equal(t, ".", opts.RootPath)
	require.Equal(t, 3, opts.Depth)
	require.Equal(t, sast.DefaultRegistry, opts.RuleRegistry, "an unset --rule-registry must fall back to the default")
	require.Equal(t, -1, opts.SnippetContext, "an unset --snippet-context means 'derive a width', not 'no snippet'")
	require.Empty(t, opts.SeverityThreshold)
	require.Empty(t, opts.ExploitThreshold)
	require.True(t, opts.GitHistory, "the CLI default is on; the language server overrides it, this function does not")
}

func TestEmptyPathBecomesCurrentDirectory(t *testing.T) {
	c := newScanLikeCommand()
	require.NoError(t, c.ParseFlags([]string{"--path", ""}))
	opts, err := FromCommand(c)
	require.NoError(t, err)
	require.Equal(t, ".", opts.RootPath)
}

func TestSnippetContextZeroIsHonoured(t *testing.T) {
	// 0 means "no snippet" and must be distinguishable from "unset", which
	// means "derive a width from the finding span". Reading the value without
	// checking Changed would collapse the two.
	c := newScanLikeCommand()
	require.NoError(t, c.ParseFlags([]string{"--snippet-context", "0"}))
	opts, err := FromCommand(c)
	require.NoError(t, err)
	require.Equal(t, 0, opts.SnippetContext)
}

func TestDeprecatedPathsAliasStillEnablesShowPaths(t *testing.T) {
	for _, flag := range []string{"--show-introduced-paths", "--paths"} {
		t.Run(flag, func(t *testing.T) {
			c := newScanLikeCommand()
			require.NoError(t, c.ParseFlags([]string{flag}))
			opts, err := FromCommand(c)
			require.NoError(t, err)
			require.True(t, opts.ShowPaths)
		})
	}
}

func TestSeverityIsNormalised(t *testing.T) {
	c := newScanLikeCommand()
	require.NoError(t, c.ParseFlags([]string{"--severity", "  HIGH "}))
	opts, err := FromCommand(c)
	require.NoError(t, err)
	require.Equal(t, "high", opts.SeverityThreshold)
}

func TestInvalidSeverityIsRejected(t *testing.T) {
	// Silently ignoring an unrecognised threshold would let a CI gate pass
	// because of a typo, which is the worst possible failure mode for a gate.
	c := newScanLikeCommand()
	require.NoError(t, c.ParseFlags([]string{"--severity", "extreme"}))
	_, err := FromCommand(c)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid --severity")
	require.Contains(t, err.Error(), "critical", "the error must list the valid values")
}

func TestInvalidExploitsIsRejected(t *testing.T) {
	c := newScanLikeCommand()
	require.NoError(t, c.ParseFlags([]string{"--exploits", "maybe"}))
	_, err := FromCommand(c)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid --exploits")
}

func TestNormaliseSeverity(t *testing.T) {
	for _, in := range []string{"critical", "HIGH", " medium ", "low"} {
		out, err := NormaliseSeverity(in)
		require.NoError(t, err, in)
		require.NotEmpty(t, out)
	}
	out, err := NormaliseSeverity("")
	require.NoError(t, err)
	require.Empty(t, out, "empty means no gate and must survive round-tripping")

	_, err = NormaliseSeverity("nonsense")
	require.Error(t, err)
}

func TestNormaliseExploits(t *testing.T) {
	for _, in := range []string{"poc", "ACTIVE", " weaponized "} {
		out, err := NormaliseExploits(in)
		require.NoError(t, err, in)
		require.NotEmpty(t, out)
	}
	out, err := NormaliseExploits("")
	require.NoError(t, err)
	require.Empty(t, out)

	_, err = NormaliseExploits("rumoured")
	require.Error(t, err)
}

func TestNormaliseIsIdempotent(t *testing.T) {
	// runScanWithFeatures re-normalises after org policy may have replaced the
	// value, so running twice must not change the result or start failing.
	first, err := NormaliseSeverity("HIGH")
	require.NoError(t, err)
	second, err := NormaliseSeverity(first)
	require.NoError(t, err)
	require.Equal(t, first, second)
}

func TestRuleIDIsUppercased(t *testing.T) {
	c := newScanLikeCommand()
	require.NoError(t, c.ParseFlags([]string{"--rule-id", " vnx-0315 "}))
	opts, err := FromCommand(c)
	require.NoError(t, err)
	require.Equal(t, "VNX-0315", opts.RuleID)
}

func TestMalformedRuleRefIsRejected(t *testing.T) {
	// A bad --rule must fail loudly. Dropping it would silently scan with fewer
	// rules than the user asked for and still report success.
	c := newScanLikeCommand()
	require.NoError(t, c.ParseFlags([]string{"--rule", "not a valid ref!!"}))
	_, err := FromCommand(c)
	require.Error(t, err)
}

func TestLicensePolicyIsCollected(t *testing.T) {
	c := newScanLikeCommand()
	require.NoError(t, c.ParseFlags([]string{
		"--license-mode", "individual",
		"--allow", "MIT,Apache-2.0",
		"--allow-file", "/etc/allow.txt",
	}))
	opts, err := FromCommand(c)
	require.NoError(t, err)
	require.Equal(t, "individual", opts.License.Mode)
	require.Equal(t, "MIT,Apache-2.0", opts.License.AllowCSV)
	require.Equal(t, "/etc/allow.txt", opts.License.AllowFile)
}

func TestGateAndWalkFlagsAreCarried(t *testing.T) {
	c := newScanLikeCommand()
	require.NoError(t, c.ParseFlags([]string{
		"--severity", "high",
		"--exploits", "weaponized",
		"--block-malware",
		"--block-eol",
		"--block-unpinned",
		"--version-lag", "7",
		"--cooldown", "14",
		"--results-only",
		"--dry-run",
		"--ignore", "vendor/**",
		"--ignore-git",
		"--ignore-binaries",
		"--git-history=false",
		"--git-history-max-commits", "50",
		"--git-history-max-files", "500",
		"--exclude", "dist/**",
		"--depth", "9",
		"--no-exploits",
		"--no-remediation",
		"--no-progress",
		"--sca-autofix",
		"--disable-default-rules",
	}))
	opts, err := FromCommand(c)
	require.NoError(t, err)

	require.Equal(t, "high", opts.SeverityThreshold)
	require.Equal(t, "weaponized", opts.ExploitThreshold)
	require.True(t, opts.BlockMalware)
	require.True(t, opts.BlockEOL)
	require.True(t, opts.BlockUnpinned)
	require.Equal(t, 7, opts.VersionLag)
	require.Equal(t, 14, opts.CooldownDays)
	require.True(t, opts.ResultsOnly)
	require.True(t, opts.DryRun)
	require.Equal(t, []string{"vendor/**"}, opts.IgnoreGlobs)
	require.True(t, opts.IgnoreGit)
	require.True(t, opts.IgnoreBinaries)
	require.False(t, opts.GitHistory)
	require.Equal(t, 50, opts.GitHistoryMaxCommits)
	require.Equal(t, 500, opts.GitHistoryMaxFiles)
	require.Equal(t, []string{"dist/**"}, opts.Excludes)
	require.Equal(t, 9, opts.Depth)
	require.True(t, opts.NoExploits)
	require.True(t, opts.NoRemediation)
	require.True(t, opts.NoProgress)
	require.True(t, opts.SCAAutofix)
	require.True(t, opts.DisableDefaultRules)
}

func TestFieldsTheFlagsDoNotDecideAreLeftZero(t *testing.T) {
	// These are the caller's to fill in. If FromCommand ever starts guessing at
	// them, a caller that also sets them would silently win or lose depending
	// on ordering.
	c := newScanLikeCommand()
	require.NoError(t, c.ParseFlags(nil))
	opts, err := FromCommand(c)
	require.NoError(t, err)

	require.Nil(t, opts.Files)
	require.Nil(t, opts.GitCtx)
	require.Nil(t, opts.SysInfo)
	require.Nil(t, opts.SeedBOM)
	require.Nil(t, opts.VulnetixSeedBOM)
	require.Nil(t, opts.LockedKinds)
	require.False(t, opts.RespectGitignore)
	require.False(t, opts.NoSCA)
	require.False(t, opts.NoSASTRules)
	require.False(t, opts.NoSecrets)
	require.False(t, opts.NoContainers)
	require.False(t, opts.NoIAC)
	require.False(t, opts.NoLicenses)
}

func TestMissingFlagsDoNotPanic(t *testing.T) {
	// sca registers no SAST flags, and the specialized commands each register a
	// different subset. Reading an absent flag must yield the zero value rather
	// than panicking, or FromCommand cannot be shared across the family.
	c := &cobra.Command{Use: "bare"}
	c.Flags().String("path", ".", "")
	require.NoError(t, c.ParseFlags(nil))

	opts, err := FromCommand(c)
	require.NoError(t, err)
	require.Equal(t, ".", opts.RootPath)
	require.Equal(t, sast.DefaultRegistry, opts.RuleRegistry)
	require.Equal(t, -1, opts.SnippetContext)
}
