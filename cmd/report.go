package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/display"
)

// reportCmd owns replaying stored scan results. It is the report view over
// .vulnetix/sbom.cdx.json — the file every scanner writes into — so it belongs to
// no single scanner and is not a scan itself: nothing is discovered, parsed or
// evaluated here.
//
// `scan --from-memory` and its --fresh-* flags are deprecated aliases that
// delegate to this command.
var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Render the stored scan results without rescanning",
	Long: `Render the results of the last scan from .vulnetix/sbom.cdx.json.

Nothing is discovered, parsed or evaluated: this reads the CycloneDX document the
scanners already wrote and prints the same tables a scan prints. It is the fast
way to look at findings again — in a shell, in CI after a scan step, or on a
machine that cannot reach the API.

By default no network calls are made at all. The --fresh-* flags opt into
targeted refreshes of individual data classes, leaving everything else as stored:

  --fresh-exploits     re-fetch exploit intelligence (KEV, PoC, weaponisation)
  --fresh-advisories   re-fetch remediation plans and fix availability
  --fresh-vulns        re-check affected version ranges and current scoring

Examples:
  vulnetix report                            # replay stored findings, offline
  vulnetix report --path ./service           # replay another project's results
  vulnetix report --fresh-exploits           # stored findings, current exploit intel
  vulnetix report --fresh-vulns              # re-check which versions are affected
  vulnetix report --fresh-exploits --fresh-advisories`,
	Args: cobra.MaximumNArgs(1),
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		printBanner(cmd)
		initDisplayContext(cmd, display.ModeText)
		applyScanDisplayFlags(cmd)
		// Credentials are optional: they are only needed for the --fresh-* refreshes.
		return resolveVDBCredentials(false)
	},
	RunE: runReport,
}

func init() {
	reportCmd.Flags().String("path", ".", "Project directory whose .vulnetix/ results are rendered")
	reportCmd.Flags().Bool("fresh-exploits", false, "Re-fetch exploit intelligence for the stored findings")
	reportCmd.Flags().Bool("fresh-advisories", false, "Re-fetch remediation plans for the stored findings")
	reportCmd.Flags().Bool("fresh-vulns", false, "Re-check affected version ranges and scoring for the stored findings")
	_ = reportCmd.MarkFlagDirname("path")
	rootCmd.AddCommand(reportCmd)
}

func runReport(cmd *cobra.Command, args []string) error {
	rootPath, _ := cmd.Flags().GetString("path")
	if len(args) == 1 && args[0] != "" {
		rootPath = args[0]
	}
	if rootPath == "" {
		rootPath = "."
	}
	freshExploits, _ := cmd.Flags().GetBool("fresh-exploits")
	freshAdvisories, _ := cmd.Flags().GetBool("fresh-advisories")
	freshVulns, _ := cmd.Flags().GetBool("fresh-vulns")

	return renderStoredReport(rootPath, freshExploits, freshAdvisories, freshVulns)
}

// renderStoredReport is the single entry point for replaying stored results. The
// `report` command, `scan --from-memory` (deprecated) and the dry-run tail all
// call it so there is one definition of "show me what the last scan found".
func renderStoredReport(rootPath string, freshExploits, freshAdvisories, freshVulns bool) error {
	if rootPath == "" {
		rootPath = "."
	}
	// LoadFromMemory resolves .vulnetix/ relative to the path it is given; keep it
	// relative to the process CWD so a relative --path behaves the same as the
	// scan commands.
	if rel, err := filepath.Rel(".", rootPath); err == nil && rel != "" {
		rootPath = rel
	}
	if err := LoadFromMemory(rootPath, freshExploits, freshAdvisories, freshVulns); err != nil {
		return fmt.Errorf("%w", err)
	}
	return nil
}
