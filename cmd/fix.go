package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/display"
)

// fixCmd owns remediation. Autofix used to be reachable only as
// `--sca-autofix` on the scan family, which left ~800 lines of remediation logic
// with no command of its own; `vulnetix fix` is that owner (the mechanics live in
// cmd/fix_autofix.go and internal/fix).
//
// It runs the SCA pipeline with autofix enabled rather than reimplementing it, so
// plan building, manifest selection, install batching, the confirmation rescan,
// VEX attestation and snapshot reporting are exactly what a scan does — there is
// one implementation, not two.
var fixCmd = &cobra.Command{
	Use:     "fix",
	Aliases: []string{"autofix"},
	Short:   "Apply validated dependency fixes, then rescan to confirm",
	Long: `Resolve vulnerable dependencies to safe versions, apply the change with the
project's own package manager, and rescan to prove the finding is gone.

A fix is only applied when a safe target version exists and the upgrade is within
policy. Packages with no vulnerability-free version are reported and attested as
risk-accepted rather than silently skipped, and every applied fix is recorded as
CycloneDX VEX so the next scan knows why the finding disappeared.

This is the SCA pipeline with remediation enabled: the same discovery, the same
VDB lookup, the same gates. "vulnetix scan --sca-autofix" and
"vulnetix sca --sca-autofix" run it as part of a wider scan.

Examples:
  vulnetix fix                            # propose and apply fixes interactively
  vulnetix fix --dry-run                  # show the plan, change nothing
  vulnetix fix --yes                      # non-interactive: safe defaults, no prompts
  vulnetix fix --strategy safest          # prefer the lowest safe version
  vulnetix fix --strategy latest          # prefer the newest version
  vulnetix fix --manifest package.json    # restrict edits to one manifest
  vulnetix fix --max-major-bump 1         # refuse targets crossing >1 major version`,
	Args: cobra.MaximumNArgs(1),
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		printBanner(cmd)
		initDisplayContext(cmd, display.ModeText)
		applyScanDisplayFlags(cmd)
		// Credentials are optional — community fallback is used when absent.
		return resolveVDBCredentials(false)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 1 && args[0] != "" {
			if err := cmd.Flags().Set("path", args[0]); err != nil {
				return err
			}
		}
		if err := applyFixFlagAliases(cmd); err != nil {
			return err
		}

		// SCA only: fixes come from dependency findings. Licenses, SAST, secrets,
		// containers and IaC have no autofix path today.
		return runScanWithFeatures(cmd.Context(), cmd,
			true,  // noSAST
			false, // noSCA
			true,  // noLicenses
			true,  // noSecrets
			true,  // noContainers
			true,  // noIAC
		)
	},
}

// fixFlagAliases maps this command's flag names onto the scan-family
// --sca-autofix-* names the engine reads.
var fixFlagAliases = map[string]string{
	"strategy":       "sca-autofix-strategy",
	"manifest":       "sca-autofix-manifest",
	"max-major-bump": "sca-autofix-max-major-bump",
}

// applyFixFlagAliases copies the remediation-friendly flags onto the engine's
// names and forces autofix on — remediation is the point of `fix`, not an opt-in.
func applyFixFlagAliases(cmd *cobra.Command) error {
	for from, to := range fixFlagAliases {
		if !cmd.Flags().Changed(from) {
			continue
		}
		value := cmd.Flags().Lookup(from).Value.String()
		if err := cmd.Flags().Set(to, value); err != nil {
			return fmt.Errorf("applying --%s: %w", from, err)
		}
	}
	return cmd.Flags().Set("sca-autofix", "true")
}

func init() {
	// The engine reads the whole scan flag set (path, depth, exclude, gates,
	// output routing), so register it and then present remediation-friendly names
	// for the autofix knobs.
	addScanFlags(fixCmd)

	// --dry-run means something different here. Everywhere else in the scan
	// family it stops before any network work; a fix plan cannot be computed
	// without the VDB's Safe-Harbour versions, so this one queries and stops
	// before touching a manifest. Saying so in the help avoids a promise of
	// "zero API calls" that the command cannot keep.
	if f := fixCmd.Flags().Lookup("dry-run"); f != nil {
		f.Usage = "Show the fix plan and change nothing. Unlike the rest of the scan family this still queries the VDB — the plan is built from it — but no manifest is edited, no install runs and no rescan runs"
	}

	fixCmd.Flags().String("strategy", "stable", "Fix target strategy: stable, safest or latest")
	fixCmd.Flags().String("manifest", "", "Restrict fixes to one manifest file")
	fixCmd.Flags().Int("max-major-bump", 0, "Refuse fix targets crossing more than N major versions (0 = no limit)")
	_ = fixCmd.RegisterFlagCompletionFunc("strategy", cobra.FixedCompletions(
		[]string{"stable", "safest", "latest"}, cobra.ShellCompDirectiveNoFileComp))

	// The scan-family spellings still work (a pipeline may pass them verbatim) but
	// are hidden here so `vulnetix fix --help` advertises one name per knob.
	// The license and secrets-stage flags come with the shared flag set and mean
	// nothing to a remediation run, so they are hidden too.
	for _, name := range []string{
		"sca-autofix", "sca-autofix-strategy", "sca-autofix-manifest", "sca-autofix-max-major-bump",
		"allow", "allow-file", "license-mode",
		"ignore", "ignore-git", "ignore-binaries",
		"git-history", "git-history-max-commits", "git-history-max-files",
		"include-ignored",
	} {
		_ = fixCmd.Flags().MarkHidden(name)
	}

	rootCmd.AddCommand(fixCmd)
}
